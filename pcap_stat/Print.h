#ifndef PRINT_H
#define PRINT_H
#include <map>
#include "Mac.h"
using namespace std;
class Print
{

public:
    void print_endpoint_ip(map<u_int32_t, int> ip_rx,map<u_int32_t, int> ip_rx_cnt,map<u_int32_t, int> ip_tx, map<u_int32_t, int>ip_tx_cnt);
    void print_endpoint_mac(map<Mac, int> mac_rx,map<Mac, int> mac_rx_cnt,map<Mac, int> mac_tx,map<Mac, int> mac_tx_cnt);
    void print_conversation_mac(map<pair<Mac,Mac>, int> mac_cnv, map<pair<Mac,Mac>, int> mac_cnv_cnt);
    void print_conversation_ip(map<pair<u_int32_t,u_int32_t>, int> ip_cnv, map<pair<u_int32_t,u_int32_t>, int>ip_cnv_cnt);
};

#endif // PRINT_H
