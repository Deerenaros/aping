#ifndef _WIN32

#include "Ping_lin.h"

#define BUFSIZE 8192
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <iostream>

struct route_info {
	in_addr dstAddr;
	in_addr srcAddr;
	in_addr gateWay;
	char ifName[IF_NAMESIZE];
};

int readNlSock( int sockFd, char *bufPtr, unsigned int seqNum, int pId ) {
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;
	do {
		if ( ( readLen = recv( sockFd, bufPtr, BUFSIZE - msgLen, 0) ) < 0 ) {
			perror("SOCK READ: ");
			return -1;
		}
		nlHdr = (struct nlmsghdr*) bufPtr;
		if ( ( NLMSG_OK( nlHdr, readLen ) == 0 ) || ( nlHdr->nlmsg_type == NLMSG_ERROR ) ) {
			perror( "Error in received packet" );
			return -1;
		}
		if ( nlHdr->nlmsg_type == NLMSG_DONE )
			break;

		bufPtr += readLen;
		msgLen += readLen;

		if ( ( nlHdr->nlmsg_flags & NLM_F_MULTI ) == 0 )
			break;
	}
	while( ( nlHdr->nlmsg_seq != seqNum ) || ( nlHdr->nlmsg_pid != (unsigned) pId ) );
	return msgLen;
}

void parseRoutes( struct nlmsghdr *nlHdr, struct route_info *rtInfo ) {
	struct rtmsg *rtMsg = (struct rtmsg*) NLMSG_DATA( nlHdr );
	
	if( ( rtMsg->rtm_family != AF_INET ) ) {
		std::cout << (int)rtMsg->rtm_family << " " << (int)AF_INET << " " << (int)rtMsg->rtm_table << " " << (int)RT_TABLE_MAIN << std::endl;
		return;
	}

	struct rtattr *rtAttr = (struct rtattr*) RTM_RTA( rtMsg );
	int rtLen = RTM_PAYLOAD( nlHdr );
	for( ; RTA_OK( rtAttr, rtLen ); rtAttr = RTA_NEXT( rtAttr, rtLen ) ) {
		switch ( rtAttr->rta_type ) {
		case RTA_OIF:
			if_indextoname( *(int*) RTA_DATA( rtAttr ), rtInfo->ifName );
			break;
		case RTA_GATEWAY:
			rtInfo->gateWay = *(in_addr*) RTA_DATA( rtAttr );
			break;
		case RTA_PREFSRC:
			rtInfo->srcAddr = *(in_addr*) RTA_DATA( rtAttr );
			break;
		case RTA_DST:
			rtInfo->dstAddr = *(in_addr*) RTA_DATA( rtAttr );
			break;
		}
	}
}

IP_t GetDefaultGatewayIP() {
	IP_t ret;

	int sock, msgSeq = 0;
	if( ( sock = socket( PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE ) ) < 0 ) {
		perror( "Socket Creation: " );
		return ret;
	}

	char msgBuf[BUFSIZE];
	memset(msgBuf, 0, BUFSIZE);
	struct nlmsghdr *nlMsg = (struct nlmsghdr*) msgBuf;

	nlMsg->nlmsg_len = NLMSG_LENGTH( sizeof( struct rtmsg ) );
	nlMsg->nlmsg_type = RTM_GETROUTE;

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq = msgSeq++;
	nlMsg->nlmsg_pid = getpid();

	if( send( sock, nlMsg, nlMsg->nlmsg_len, 0 ) < 0 )
		return ret;

	int len;
	if( ( len = readNlSock( sock, msgBuf, msgSeq, getpid() ) ) < 0 )
		return ret;

	struct route_info *rtInfo = (struct route_info*) malloc( sizeof( struct route_info ) );

	for( ; NLMSG_OK( nlMsg, len ); nlMsg = NLMSG_NEXT( nlMsg, len ) ) {
		memset( rtInfo, 0, sizeof( struct route_info ) );
		parseRoutes( nlMsg, rtInfo );

		if( strstr( (char*) inet_ntoa( rtInfo->dstAddr ), "0.0.0.0" ) && !strstr( (char*) inet_ntoa( rtInfo->gateWay ), "0.0.0.0" ) ) {
			char buf[64];
			inet_ntop( AF_INET, &rtInfo->gateWay, buf, sizeof( buf ) );
			ret = buf;
			break;
		}
	}

	free( rtInfo );
	close( sock );
	return ret;
}

#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define PACKETSIZE  64

struct icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union
	{
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t dummy;
			uint16_t mtu;
		} frag;
	} un;
};

struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

int pid = -1;
struct protoent *proto = NULL;
int cnt = 1;

struct __attribute__((packed)) arp_header
{
	unsigned short arp_hd;
	unsigned short arp_pr;
	unsigned char arp_hdl;
	unsigned char arp_prl;
	unsigned short arp_op;
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_dha[6];
	unsigned char arp_dpa[4];
};

unsigned short checksum(void *b, int len)
{
	unsigned short *buf = (unsigned short*) b;
	unsigned int sum = 0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

size_t Ping( const IP_t &ip )
{
	const int val=255;
	int i, sd;
	struct packet pckt;
	struct sockaddr_in r_addr;
	int loop;
	struct hostent *hname;
	struct sockaddr_in addr_ping,*addr;

	pid = getpid();
	hname = gethostbyname(ip.c_str());
	bzero(&addr_ping, sizeof(addr_ping));
	addr_ping.sin_family = hname->h_addrtype;
	addr_ping.sin_port = 0;
	addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

	addr = &addr_ping;

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);//1/*proto->p_proto*/);
	if ( sd < 0 ) {
		perror("socket");
		return INV;
	}
	if ( setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0) {
		perror("Set TTL option");
		return INV;
	}
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if ( setsockopt( sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof( tv ) ) < 0 ) {
		perror("Timeout");
		return INV;
	}

	bzero( &pckt, sizeof( pckt ) );
	pckt.hdr.type = ICMP_ECHO;
	pckt.hdr.un.echo.id = pid;
	for ( i = 0; i < sizeof( pckt.msg ) - 1; i++ )
		pckt.msg[i] = i + '0';
	pckt.msg[i] = 0;
	pckt.hdr.un.echo.sequence = cnt++;
	pckt.hdr.checksum = checksum( &pckt, sizeof( pckt ) );

	struct timeval _start, _end;
	gettimeofday( &_start, NULL );
	size_t start = _start.tv_sec * 1000000 + _start.tv_usec;

	if ( sendto( sd, &pckt, sizeof( pckt ), 0, (struct sockaddr*) addr, sizeof( *addr ) ) <= 0 )
		perror( "sendto" );

	socklen_t len = sizeof( r_addr );

	if( recvfrom( sd, &pckt, sizeof( pckt ), 0, (struct sockaddr*) &r_addr, &len ) > 0 ) {
		gettimeofday( &_end, NULL );
		size_t end = _end.tv_sec * 1000000 + _end.tv_usec;
		return end - start;
	}
	
	return INV;
}

#endif