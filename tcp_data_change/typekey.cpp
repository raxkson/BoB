#include "typekey.h"

bool TcpFlowkey::operator<(const TcpFlowkey &rhs) const
{
    if (this->srcIp   < rhs.srcIp)   return true;
    if (this->srcIp   > rhs.srcIp)   return false;
    if (this->srcPort < rhs.srcPort) return true;
    if (this->srcPort > rhs.srcPort) return false;
    if (this->dstIp   < rhs.dstIp)   return true;
    if (this->dstIp   > rhs.dstIp)   return false;
    if (this->dstPort < rhs.dstPort) return true;
    return false;
}
bool TcpFlowkey::operator=(const TcpFlowkey &rhs) const
{
    if (this->srcIp   != rhs.srcIp)   return false;
    if (this->srcIp   != rhs.srcIp)   return false;
    if (this->srcPort != rhs.srcPort) return false;
    if (this->srcPort != rhs.srcPort) return false;
    if (this->dstIp   != rhs.dstIp)   return false;
    if (this->dstIp   != rhs.dstIp)   return false;
    if (this->dstPort != rhs.dstPort) return false;
    return true;
}
