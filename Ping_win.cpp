#ifdef _WIN32

#include "Ping_win.h"
#include <WinSock2.h>
#include <wbemidl.h>
#include <windows.h>
#include <comdef.h>
#include <winsock.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wbemuuid.lib")

IP_t GetDefaultGatewayIP()
{
	IP_t ret;

	CoInitialize( NULL );
	if( CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0 ) != S_OK )
		return ret;

	IWbemLocator *pLoc = NULL;
	if( CoCreateInstance( CLSID_WbemAdministrativeLocator, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, IID_IUnknown, (void**) &pLoc ) != S_OK )
		return ret;

	IWbemServices *pSvc = NULL;
	if( pLoc->ConnectServer( L"root\\cimv2", NULL, NULL, NULL, 0, NULL, NULL, &pSvc ) != S_OK )
		return ret;

	IEnumWbemClassObject *pEnumerator = NULL;
	HRESULT hr = pSvc->ExecQuery( L"WQL", L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'TRUE'", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );
	if( FAILED( hr ) ) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return ret;
	}

	IWbemClassObject *pclsObj = NULL;
	while( pEnumerator && ret.empty() ) {
		_variant_t vaDefaultIPGateway;
		ULONG uReturn;
		hr = pEnumerator->Next( WBEM_INFINITE, 1, &pclsObj, &uReturn );
		if( !uReturn )
			break;

		hr = pclsObj->Get( L"DefaultIPGateway", 0, &vaDefaultIPGateway, NULL, NULL );
		if( hr == WBEM_S_NO_ERROR && vaDefaultIPGateway.vt != VT_NULL ) {
			LONG lLow = 0;
			LONG lUp = 0;
			SafeArrayGetLBound( vaDefaultIPGateway.parray, 1, &lLow );
			SafeArrayGetUBound( vaDefaultIPGateway.parray, 1, &lUp );
			for( LONG i = lLow; i <= lUp; ++i ) {
				BSTR bsDefaultIPGateway;
				if( SafeArrayGetElement( vaDefaultIPGateway.parray, &i, &bsDefaultIPGateway ) == S_OK ) {
					char buf[64];
					WideCharToMultiByte( CP_OEMCP, 0, bsDefaultIPGateway, -1, buf, sizeof( buf ), NULL, NULL );
					SysFreeString( bsDefaultIPGateway );
					int32_t tmp[4];
					if( sscanf_s( buf, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3] ) == 4 ) {
						ret = buf;
						break;
					}
				}
			}
		}
		VariantClear( &vaDefaultIPGateway );
	}

	if( pclsObj )
		pclsObj->Release();
	if( pEnumerator )
		pEnumerator->Release();
	if( pSvc )
		pSvc->Release();
	if( pLoc )
		pLoc->Release();
	CoUninitialize();
	return ret;
}

#pragma pack(1)

// The IP header
struct IPHeader {
	BYTE h_len:4;     // Length of the header in dwords
	BYTE version:4;   // Version of IP
	BYTE tos;         // Type of service
	USHORT total_len; // Length of the packet in dwords
	USHORT ident;     // unique identifier
	USHORT flags;     // Flags
	BYTE ttl;         // Time to live
	BYTE proto;       // Protocol number (TCP, UDP etc)
	USHORT checksum;  // IP checksum
	ULONG source_ip;
	ULONG dest_ip;
};

// ICMP header
struct ICMPHeader {
	BYTE type;        // ICMP packet type
	BYTE code;        // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
	ULONG timestamp;  // not part of ICMP, but we need it
};

#pragma pack()

USHORT ip_checksum( USHORT *buffer, size_t size )
{
	uint32_t cksum = 0;

	while( size > 1 ) {
		cksum += *buffer++;
		size -= sizeof( USHORT );
	}
	if( size ) {
		cksum += *(UCHAR*) buffer;
	}

	cksum = ( cksum >> 16 ) + ( cksum & 0xffff );
	cksum += ( cksum >> 16 );
	
	return (USHORT) ~cksum;
}

#define ICMP_MIN 8
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRE 11
#define ICMP_ECHO_REQUEST 8

int decode_reply(IPHeader* reply, int bytes, sockaddr_in* from) 
{
	unsigned short header_len = reply->h_len * 4;
	ICMPHeader *icmphdr = (ICMPHeader*)( (char*) reply + header_len );

	if ( bytes < header_len + ICMP_MIN )
		return -1;
	else if ( icmphdr->type != ICMP_ECHO_REPLY && icmphdr->type != ICMP_TTL_EXPIRE )
		return -1;
	else if ( icmphdr->id != (USHORT) GetCurrentProcessId() )
		return -2;

	return 0;
}

size_t Ping( const IP_t &ip )
{
	size_t ret = INV;
	WSAData wsaData;
	if ( WSAStartup( MAKEWORD( 2, 1 ), &wsaData ) != 0 )
		return ret;

	SOCKET sd = WSASocket( AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, 0 );
	if( sd == INVALID_SOCKET ) {
		std::cout << "Error creating socket! Try running program by the administrator" << std::endl;
		goto cleanup;
	}
	int32_t ttl = 30;
	if( setsockopt( sd, IPPROTO_IP, IP_TTL, (const char*) &ttl, sizeof( ttl ) ) == SOCKET_ERROR)
		goto cleanup;
	sockaddr_in dst;
	memset( &dst, 0, sizeof( dst ) );
	uint32_t addr = inet_addr( ip.c_str() );
	if( addr != INADDR_NONE ) {
		dst.sin_addr.s_addr = addr;
		dst.sin_family = AF_INET;
	}
	else {
		hostent *hp = gethostbyname( ip.c_str() );
		if (hp != 0) {
			memcpy( &dst.sin_addr, hp->h_addr, hp->h_length);
			dst.sin_family = hp->h_addrtype;
		}
		else
			goto cleanup;
	}

	static const int32_t packetSize = max( sizeof( ICMPHeader ), 32 );
	uint8_t _sendBuf[packetSize];
	ICMPHeader *sendBuf = (ICMPHeader*) _sendBuf;

	sendBuf->type = ICMP_ECHO_REQUEST;
	sendBuf->code = 0;
	sendBuf->checksum = 0;
	sendBuf->id = (USHORT)GetCurrentProcessId();
	sendBuf->seq = 0;
	sendBuf->timestamp = GetTickCount();
	
	static const uint32_t deadmeat = 0xDEADBEEF;
	char *datapart = (char*) sendBuf + sizeof( ICMPHeader );
	int bytes_left = packetSize - sizeof(ICMPHeader);
	while (bytes_left > 0) {
		memcpy(datapart, &deadmeat, min(int(sizeof(deadmeat)), bytes_left));
		bytes_left -= sizeof(deadmeat);
		datapart += sizeof(deadmeat);
	}

	sendBuf->checksum = ip_checksum( (USHORT*) sendBuf, packetSize );

	sockaddr_in src;
	char _rcvBuf[1024 + sizeof( IPHeader )];
	IPHeader *rcvBuf = (IPHeader*) _rcvBuf;

	LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds;
	LARGE_INTEGER Frequency;
	QueryPerformanceFrequency( &Frequency );
	QueryPerformanceCounter( &StartingTime );

	if( sendto( sd, (char*) sendBuf, packetSize, 0, (sockaddr*) &dst, sizeof( dst ) ) != SOCKET_ERROR ) {
		while( 1 ) {
			int32_t fromLen = sizeof( src );
			if( recvfrom( sd, (char*) rcvBuf, sizeof( _rcvBuf ), 0, (sockaddr*) &src, &fromLen ) == SOCKET_ERROR ) {
				unsigned short header_len = rcvBuf->h_len * 4;
				ICMPHeader *icmphdr = (ICMPHeader*) ( (char*)rcvBuf + header_len );
				if( icmphdr->seq != 0 )
					continue;
				break;
			}
			if( decode_reply( rcvBuf, packetSize, &src ) == 0 ) {
				QueryPerformanceCounter( &EndingTime );
				ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
				ElapsedMicroseconds.QuadPart *= 1000000;
				ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;
				ret = ElapsedMicroseconds.QuadPart;
			}
			break;
		}
	}

cleanup:
	WSACleanup();
	return ret;
}

#endif // _WIN32
