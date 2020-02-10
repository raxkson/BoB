#ifndef PRINT_H
#define PRINT_H
#include <iostream>
class PrintInfo
{
private:
    // BSSID, PWR, CH, ESSID
    uint8_t BSSID[6];
    uint8_t PWR;
    uint16_t CH;
    char MB[4];
    char ENC[4];
    uint8_t *ESSID;
    uint8_t beacon = 0;

public:
    PrintInfo(uint8_t *bssid, uint8_t pwr, uint16_t ch, uint8_t *essid, uint8_t essid_len, uint16_t enc, uint8_t mb);
    int getAbit(unsigned short x, int n)    // for ENC
    {
      return (x & (1 << n)) >> n;
    }
    void Show() const;
};
#endif // PRINT_H
