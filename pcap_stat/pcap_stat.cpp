#include <pcap.h>
#include <map>
#include <iostream>
#include "Print.h"
#include "packet.h"
using namespace std;
void usage() {
  printf("syntax: pcap_stat <pcap file name>\n");
  printf("sample: pcap_test test.pcap\n");
}
int main(int argc, char *argv[])
{

    if(argc != 2){
        usage();
        return -1;
    }

    string file = argv[1];

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

    //endpoint(mac, ip)
    map<u_int32_t, int> endpoint_ip_rx;//packet count //packet bytes
    map<u_int32_t, int> endpoint_ip_rx_cnt;
    map<Mac, int> endpoint_mac_rx;
    map<Mac, int> endpoint_mac_rx_cnt;

    map<u_int32_t, int> endpoint_ip_tx;//packet count //packet bytes
    map<u_int32_t, int> endpoint_ip_tx_cnt;
    map<Mac, int> endpoint_mac_tx;
    map<Mac, int> endpoint_mac_tx_cnt;

    //conversation(smac-dmac, sip-dip)

    map<pair<u_int32_t, uint32_t>, int> conversation_ip;
    map<pair<u_int32_t, u_int32_t>, int> conversation_ip_cnt;

    map<pair<Mac,Mac>, int> conversation_mac;
    map<pair<Mac,Mac>, int> conversation_mac_cnt;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            //printf("   * Invalid IP header length: %u bytes\n", size_ip);
            continue;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            continue;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


        //endpoint /////////////////////////////////////////////////////////////////
        //rx packet
        //ip rx endpoint
        if (endpoint_ip_rx.find(ip->ip_src) == endpoint_ip_rx.end()){
            endpoint_ip_rx.insert(make_pair(ip->ip_src,header->caplen));
            endpoint_ip_rx_cnt.insert(make_pair(ip->ip_src,1));
        }else {
            endpoint_ip_rx[ip->ip_src] += header->caplen;
            endpoint_ip_rx_cnt[ip->ip_src] += 1;
        }
        //mac rx endpoint
        if (endpoint_mac_rx.find(ethernet->ether_shost) == endpoint_mac_rx.end()){
            endpoint_mac_rx.insert(make_pair(ethernet->ether_shost, header->caplen));
            endpoint_mac_rx_cnt.insert(make_pair(ethernet->ether_shost,1));
        }else {
            endpoint_mac_rx[ethernet->ether_shost] += header->caplen;
            endpoint_mac_rx_cnt[ethernet->ether_shost] += 1;
        }
        //tx packet
        //ip tx endpoint
        if (endpoint_ip_tx.find(ip->ip_dst) == endpoint_ip_tx.end()){
            endpoint_ip_tx.insert(make_pair(ip->ip_dst,header->caplen));
            endpoint_ip_tx_cnt.insert(make_pair(ip->ip_dst,1));
        }else {
            endpoint_ip_tx[ip->ip_dst] += header->caplen;
            endpoint_ip_tx_cnt[ip->ip_dst] += 1;
        }
        //mac tx endpoint
        if (endpoint_mac_tx.find(ethernet->ether_dhost) == endpoint_mac_tx.end()){
            endpoint_mac_tx.insert(make_pair(ethernet->ether_dhost, header->caplen));
            endpoint_mac_tx_cnt.insert(make_pair(ethernet->ether_dhost,1));
        }else {
            endpoint_mac_tx[ethernet->ether_dhost] += header->caplen;
            endpoint_mac_tx_cnt[ethernet->ether_dhost] += 1;
        }

        //conversation ////////////////////////////////////////////////////////////////
        //ip conversation
        pair<u_int32_t, u_int32_t> ip_pair;
        ip_pair = make_pair(ip->ip_src, ip->ip_dst);
        if(conversation_ip.find(ip_pair) == conversation_ip.end()){
            conversation_ip.insert(make_pair(ip_pair, header->caplen));
            conversation_ip_cnt.insert(make_pair(ip_pair,1));
        }else {
            conversation_ip[ip_pair] += header->caplen;
            conversation_ip_cnt[ip_pair] += 1;
        }
        //mac conversation
        auto mac_pair = make_pair(ethernet->ether_shost, ethernet->ether_dhost);
        if(conversation_mac.find(mac_pair) == conversation_mac.end()){
            conversation_mac.insert(make_pair(mac_pair, header->caplen));
            conversation_mac_cnt.insert(make_pair(mac_pair, 1));
        } else {
            conversation_mac[mac_pair] += header->caplen;
            conversation_mac_cnt[mac_pair] += 1;
        }

    }

    Print print;
    cout << "-----------------------------------------------ENDPOINT-----------------------------------------------" << endl;
    print.print_endpoint_ip(endpoint_ip_tx, endpoint_ip_tx_cnt, endpoint_ip_rx, endpoint_ip_rx_cnt);
    print.print_endpoint_mac(endpoint_mac_rx, endpoint_mac_rx_cnt, endpoint_mac_tx, endpoint_mac_tx_cnt);
    cout << "---------------------------------------------CONVERSATION---------------------------------------------" << endl;
    print.print_conversation_ip(conversation_ip, conversation_ip_cnt);
    print.print_conversation_mac(conversation_mac, conversation_mac_cnt);
}
