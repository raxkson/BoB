#include "TCPDataChange.h"
string replaceString(string subject, const string &from, const string &to)
{
    size_t pos = 0;
    while((pos = subject.find(from, pos)) != string::npos)
    {
        subject.replace(pos, from.length(), to);
        pos += to.length();
    }
    return subject;
}

uint16_t calcChecksum(uint16_t *data, uint32_t len)
{
    uint8_t oddbyte = 0;
    uint32_t sum = 0;

    while(len > 1)
    {
            sum += ntohs(*data++);
            len -= 2;
    }

    if(len == 1){
        oddbyte = (uint8_t)*data;
        sum += ntohs(oddbyte);
    }

    sum = (sum >> 16) + (sum & 0xffff);

    return (uint16_t)sum;
}

uint16_t checksum(uint8_t *data, uint32_t len)
{
    struct checksum_header cs;
    struct ipv4_hdr *ip;
    struct tcp_hdr *tcp;

    // set ip, tcp header
    ip = (struct ipv4_hdr *)data;
    data += sizeof(struct ipv4_hdr);
    tcp = (struct tcp_hdr *)data;
    tcp->th_sum = 0x00;

    // set checksum
    memcpy(&cs.ip_src, &ip->ip_src, sizeof(ip->ip_src));
    memcpy(&cs.ip_dst, &ip->ip_dst, sizeof(ip->ip_dst));
    cs.proto = ip->ip_p;
    cs.tcp_len = htons(len - (ip->ip_hl * 4));

    // calc checksum
    uint16_t pseudo_checksum = calcChecksum((uint16_t *)&cs, sizeof(cs));
    uint16_t tcp_checksum = calcChecksum((uint16_t *)tcp, ntohs(cs.tcp_len));

    uint16_t total_checksum;
    int sum = pseudo_checksum + tcp_checksum;

    total_checksum = (sum >> 16) + (sum & 0xffff);

    total_checksum = ntohs(~total_checksum);
    tcp->th_sum = total_checksum;

    return total_checksum;
}
