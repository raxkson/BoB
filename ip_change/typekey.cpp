#include "typekey.h"
bool IPFlowkey::operator==(const IPFlowkey &rhs) const
{
    if (this->ip_   != rhs.ip_)   return false;
    if (this->port_   != rhs.port_)   return false;
    return true;
}
