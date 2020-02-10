#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/in.h> // for uint8_t
#include <string.h>
#include <map>
#include <tuple>
#include "airodump.h"
#include "print.h"
using namespace std;
void usage()
{
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}
void print_menu(int check)
{
    if(check == 1)
    {
        printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
    }

    if(check == 2)
    {
        printf(" BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n\n");
    }
}
void printByHexData(u_int8_t *printArr, int length)
{
    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";
    }
    cout<<dec<<endl;
}

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device : %s : %s\n", dev, errbuf);
        return -1;
    }

    system("clear");
    print_menu(1);

    map <uint64_t, uint16_t> key;

    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        radio = (struct radiotap_header *)packet;
        packet += sizeof(struct radiotap_header);

        beacon = (struct beacon_header *)packet;
        packet += sizeof(struct beacon_header);

        wireless = (struct wireless_header *)packet;
        packet += sizeof(struct wireless_header);

        uint8_t essid[wireless->ssid_len];
        memcpy(essid, packet, wireless->ssid_len);

        if(beacon->frame_control_field == 0x80) //beacon
        {
            uint64_t *b;
            uint16_t c = radio->channel_frequency;
            memcpy(&b, &beacon->bss_id, 6);

            pair<uint64_t*, uint16_t> key(b, c);
            PrintInfo x(beacon->bss_id, radio->ssi_signal, radio->channel_frequency, essid, wireless->ssid_len, wireless->capabilities_info, radio->data_rate);

            x.Show();
        }

        if(beacon->frame_control_field == 0x40) //probe request
        {
            print_menu(2);
            printf(" ");
            for(int i = 0; i < 6; i++)
            {
                printf("%02X",beacon->bss_id[i]);
                if(i != 5)
                    printf(":");
            }
            cout << endl << endl;
        }
    }
    pcap_close(handle);
    return 0;
}
