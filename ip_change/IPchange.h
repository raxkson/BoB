#ifndef IPCHANGE_H
#define IPCHANGE_H
#include <iostream>
#include <cstdlib>
#include <cstring>                    // For memcpy()
#include <sys/socket.h>
#include <netinet/in.h>                // IPPROTO_ICMP
#include <netinet/ip.h>                // struct ip
#include <netinet/ip_icmp.h>        // stuct icmp
#include <arpa/inet.h>                // inet_ntoa, inet_addr

using namespace std;


#pragma pack(push,1)

struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};

#pragma pack(pop)
#define CARRY 65536

uint16_t IPChecksum(uint8_t* data);
#endif // IPCHANGE_H
