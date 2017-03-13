#ifndef PING_H
#define PING_H

#include <cstdint>
#include <string>

#ifdef _WIN32
	#include <iostream>
	#define sscanf sscanf_s
#endif

typedef std::string IP_t;

const size_t INV = (size_t) -1;

inline bool IpValid( const IP_t &ip ) {
	return !ip.empty();
}

IP_t GetDefaultGatewayIP();
size_t Ping( const IP_t &ip );

#endif // PING_H
