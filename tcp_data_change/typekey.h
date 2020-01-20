#ifndef TYPEKEY_H
#define TYPEKEY_H
#include <iostream>
class TcpFlowkey{
public:
    uint32_t srcIp;
    uint16_t srcPort;
    uint32_t dstIp;
    uint16_t dstPort;

    bool operator < (const TcpFlowkey& rhs) const;
    bool operator == (const TcpFlowkey& rhs) const;
    TcpFlowkey reverse();

};

#endif // TYPEKEY_H
