#ifndef AIRODUMP_H
#define AIRODUMP_H
#include <iostream>
struct radiotap_header *radio;
struct beacon_header *beacon;
struct wireless_header *wireless;
struct radiotap_header  // 56byte
{
    uint8_t header_version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag[2];
    uint8_t flag;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flag;
    uint8_t ssi_signal;
    uint8_t ssi_noise;
    uint8_t antenna;
    uint8_t dummy;
    uint8_t vendor_namespace1[9];
    uint8_t vendor_namespace2[12];
};
struct beacon_header    // 24byte
{
    uint16_t frame_control_field;
    uint16_t duration;
    uint8_t recv_dest_addr[6];  // receiver, destination address
    uint8_t trans_src_addr[6];  // transmitter, source address
    uint8_t bss_id[6];
    uint16_t frag_seq_num;  // fagment, sequence number
};
struct wireless_header // changed byte
{
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capabilities_info;
    uint8_t ssid_pra_set;
    uint8_t ssid_len;
};
#endif // AIRODUMP_H
