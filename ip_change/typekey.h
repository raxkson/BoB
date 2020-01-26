#ifndef TYPEKEY_H
#define TYPEKEY_H
#include <iostream>
class IPFlowkey{
public:
    u_int32_t ip_;
    u_int16_t port_;

    IPFlowkey(){}
    IPFlowkey(u_int32_t ip, u_int16_t port) : ip_(ip), port_(port) {}

    bool operator < (const IPFlowkey& rhs) const {
                if (this->ip_   < rhs.ip_) return true;
                if (this->ip_   > rhs.ip_) return false;
                if (this->port_ < rhs.port_) return true;
                return false;
    }
    bool operator == (const IPFlowkey& rhs) const;
};

#endif // TYPEKEY_H
