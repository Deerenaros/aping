#if !defined( _WIN32 ) && !defined( PING_LIN_H )
#define PING_LIN_H

#include <stdint.h>
#include <string>

typedef std::string IP_t;

const size_t INV = (size_t) -1;

IP_t GetDefaultGatewayIP();
inline bool IpValid( const IP_t &ip ) {
	return !ip.empty();
}
size_t Ping( const IP_t &ip );

#endif // PING_LIN_H
