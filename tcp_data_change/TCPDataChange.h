#ifndef TCPDATACHANGE_H
#define TCPDATACHANGE_H

#include "pcap_packet.h"
#include <iostream>
#include <cstring>


using namespace std;
string replaceString(string subject, const string &from, const string &to);
uint16_t calcChecksum(uint16_t *data, uint32_t len);
uint16_t checksum(uint8_t *data, uint32_t len);
#endif // TCPDATACHANGE_H
