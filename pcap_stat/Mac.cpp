
//mac.cpp
#include "Mac.h"
#include <cstring>
#include <string>

Mac::Mac()
{

}

Mac& Mac::operator=(char *addr)
{
    memcpy(this->macAddr,addr,6);

    return *this;

}


Mac& Mac::operator=(u_char *addr)
{
    memcpy(this->macAddr,addr,6);

    return *this;

}


Mac& Mac::operator=(Mac &other)
{
    memcpy(this->macAddr,other.macAddr,6);

    return *this;

}
void Mac::toString() const{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", this->macAddr[0], this->macAddr[1], this->macAddr[2], this->macAddr[3], this->macAddr[4], this->macAddr[5]);
}

