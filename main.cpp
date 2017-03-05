#ifdef _WIN32
#include "Ping_win.h"

extern "C" {
#include "port/getopt.h"
}
#else
#include "Ping_lin.h"

extern "C" {
#include "getopt.h"
}

#define sscanf_s sscanf
#endif

#include <cstring>
#include <cstdlib>
#include <iostream>


void print_usage()
{
	std::cout << "Usage: [--number/-n %d] [--remote/-r %d]" << std::endl;
}

// Workaround Big/Little endian
template<typename T>
void bin_print(std::ostream &os, T data) {
    char* bytes = reinterpret_cast<char*>(&data);
    size_t size = sizeof(T);
    for(size_t i = 0; i < size; i++) {
        os.put(bytes[i]);
    }
}

int main( int argc, char **argv )
{
	size_t count = 4;
    int verbose = 0, opti = 0, c;
    char *remote = NULL;
    char *fallback = NULL;

    struct option long_options[] =
    {
        { "number",  required_argument, NULL, 'n' },
        { "remote",  required_argument, NULL, 'r' },
        { "fallback",  required_argument, NULL, 'f' },
        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "n:r:", long_options, &opti)) != -1)
    {
        switch (c)
        {
            case 0:
                std::cout << "wut?" << std::endl;
                break;

            case 'n':
                sscanf_s(optarg, "%d", &count);
                break;

            case 'r':
                if (!IpValid(optarg))
                {
                    std::cerr << "Remote --remote must be valid ip address" << std::endl;
                    exit(1);
                }
                remote = optarg;
                break;
            
            case 'f':
                    if (!IpValid(optarg))
                    {
                        std::cerr << "Remote --fallback must be valid ip address" << std::endl;
                        exit(1);
                    }
                    remote = optarg;
                    break;

            default:
                exit(1);
        }
    }

	IP_t gatewayIP = (remote != NULL ? remote : GetDefaultGatewayIP());
	if( !IpValid( gatewayIP ) ) {
		std::cerr << "Failed to determine default gateway IP!" << std::endl;
		return -1;
	}

	std::cerr << "Gateway IP: " << gatewayIP << std::endl;

	for( size_t i = 0; i < count; ++i ) {
		size_t micros = Ping( gatewayIP );
		if( micros != INV ) {
			std::cerr << "Ping. Microseconds: " << micros << std::endl;
			bin_print(std::cout, micros);
		}
		else {
			std::cerr << "Ping failed" << std::endl;
		}
	}

	return 0;
}