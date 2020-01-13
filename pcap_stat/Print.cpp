#include "Print.h"
#include <arpa/inet.h>
void Print::print_endpoint_ip(map<u_int32_t, int> ip_rx,map<u_int32_t, int> ip_rx_cnt,map<u_int32_t, int> ip_tx, map<u_int32_t, int>ip_tx_cnt)
{
    printf("<IP ENDPOINT>\nIP Address\tPackets\t\tBytes\t\tTx Packets\tTx Bytes \tRx Packets\tRx Bytes\n");
    for (auto itr = ip_rx.begin(); itr != ip_rx.end(); ++itr){
        cout << inet_ntoa(*(in_addr*)(&itr->first)) << "\t";
        cout << ip_tx_cnt[itr->first] + ip_rx_cnt[itr->first] << "\t\t";
        cout << ip_tx[itr->first] + ip_rx[itr->first] << "\t\t";
        cout << ip_tx_cnt[itr->first] << "\t\t";
        cout << ip_tx[itr->first] << "\t\t";
        cout << ip_rx_cnt[itr->first] << "\t\t";
        cout << ip_rx[itr->first] << endl;
    }
}
void Print::print_endpoint_mac(map<Mac, int> mac_rx,map<Mac, int> mac_rx_cnt,map<Mac, int> mac_tx,map<Mac, int> mac_tx_cnt){
    printf("<MAC ENDPOINT>\nMac Address\t\tPackets\t\tBytes\t\tTx Packets\tTx Bytes \tRx Packets\tRx Bytes\n");
    for (auto itr = mac_rx.begin(); itr != mac_rx.end(); ++itr){
        itr->first.toString();
        cout << "\t";
        cout << mac_tx_cnt[itr->first] + mac_rx_cnt[itr->first] << "\t\t";
        cout << mac_tx[itr->first] + mac_rx[itr->first] << "\t\t";
        cout << mac_tx_cnt[itr->first] << "\t\t";
        cout << mac_tx[itr->first] << " \t \t";
        cout << mac_rx_cnt[itr->first] << "\t\t";
        cout << mac_rx[itr->first] << endl;
    }
}
void Print::print_conversation_mac(map<pair<Mac,Mac>, int> mac_cnv, map<pair<Mac,Mac>, int> mac_cnv_cnt){
    printf("<MAC CONVERSATION>\nMac Address A\t\tMac Address B\t\tPackets\t\tBytes\t\tPackets A->B\tBytes  A->B\tPackets B->A\tBytes B->A\n");
    for (auto itr = mac_cnv.begin(); itr != mac_cnv.end(); ++itr){

        auto tmp = make_pair(itr->first.second, itr->first.first);

        itr->first.first.toString();
        cout << "\t";
        itr->first.second.toString();
        cout << "\t";
        cout << mac_cnv_cnt[itr->first] + mac_cnv_cnt[tmp];
        cout << "\t\t";
        cout << mac_cnv[itr->first] + mac_cnv[tmp];
        cout << "\t\t";
        cout << mac_cnv_cnt[itr->first];
        cout << "\t\t";
        cout << mac_cnv[itr->first];
        cout << "\t\t";
        cout << mac_cnv_cnt[tmp];
        cout << "\t\t";
        cout << mac_cnv[tmp];
        cout << endl;
        mac_cnv.erase(tmp);
        mac_cnv_cnt.erase(tmp);
        //cout << mac_rx[itr->first];
    }
}
void Print::print_conversation_ip(map<pair<u_int32_t,u_int32_t>, int> ip_cnv, map<pair<u_int32_t,u_int32_t>, int>ip_cnv_cnt){
    printf("<"
           "IP CONVERSATION>\nIP Address A\t\tIP Address B\t\tPackets\t\tBytes\t\tPackets A->B\tBytes  A->B\tPackets B->A\tBytes B->A\n");
    for (auto itr = ip_cnv.begin(); itr != ip_cnv.end(); ++itr){

        auto tmp = make_pair(itr->first.second, itr->first.first);
        cout << inet_ntoa(*(in_addr*)(&itr->first.first)) << "\t\t";
        cout << inet_ntoa(*(in_addr*)(&itr->first.second)) << "\t";
        cout << "\t";
        cout << ip_cnv_cnt[itr->first] + ip_cnv_cnt[tmp];
        cout << "\t\t";
        cout << ip_cnv[itr->first] + ip_cnv[tmp];
        cout << "\t\t";
        cout << ip_cnv_cnt[itr->first];
        cout << "\t\t";
        cout << ip_cnv[itr->first];
        cout << "\t\t";
        cout << ip_cnv_cnt[tmp];
        cout << "\t\t";
        cout << ip_cnv[tmp];
        cout << endl;
        ip_cnv.erase(tmp);
        ip_cnv_cnt.erase(tmp);

        //cout << mac_rx[itr->first];
    }
}
