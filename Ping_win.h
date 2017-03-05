#if defined( _WIN32 ) && !defined( PING_WIN_H )
#define PING_WIN_H

#include <stdint.h>
#include <iostream>
#include <string>

#define sscanf sscanf_s

typedef std::string IP_t;

const size_t INV = (size_t) -1;

IP_t GetDefaultGatewayIP();
inline bool IpValid( const IP_t &ip ) {
	return !ip.empty();
}
size_t Ping( const IP_t &ip );

#endif // PING_WIN_H
