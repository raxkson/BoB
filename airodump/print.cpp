#include "print.h"
#include <string.h>

PrintInfo::PrintInfo(uint8_t *bssid, uint8_t pwr, uint16_t ch, uint8_t *essid, uint8_t essid_len, uint16_t enc, uint8_t mb)
{
    // BSSID
    for(int i = 0; i < 6; i++)
    {
        BSSID[i] = *(bssid + i);
    }

    // PWR
    PWR = ~pwr;
    PWR += 1;

    // Beacon
    beacon += 1;

    // CH
    CH = ch % 2412 / 5 + 1;

    // MB
    switch(mb)
    {
    case 0x02:
        strcpy(MB, "11");   // 802.11b
        break;

    case 0x0c:
        strcpy(MB, "54");   // 802.11g
        break;
    }

    // ENC
    if(getAbit(enc, 4))
        strncpy(ENC, "CRT", 4);
    else
        strncpy(ENC, "OPN", 4);

    // ESSID
    memcpy(&ESSID, &essid, essid_len);
}

inline void PrintInfo::Show() const
{
    // Print BSSID
    printf(" ");
    for(int i = 0; i < 6; i++)
    {
        printf("%02X",BSSID[i]);
        if(i != 5)
            printf(":");
    }

    // Print PWR, CH, ESSID
    printf("  -%d                         %2d  %s   %s              %s\n", PWR, CH, MB, ENC, ESSID);
}
