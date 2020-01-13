//mac.h
#ifndef MAC_H
#define MAC_H
#include <cstring>
#include <iostream>

class Mac
{

public:
    u_char macAddr[6];

    Mac();
    Mac& operator=(char *addr);
    Mac& operator=(u_char *addr);
    Mac& operator=(Mac &other);
    Mac& operator<(Mac &other);

    void toString() const;

    bool operator<(const Mac &other) const
    {
        if(memcmp(macAddr, other.macAddr, 6) < 0){
            return true;
        }else{
            return false;
        }
    }
};

#endif // MAC_H
