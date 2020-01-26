#ifndef PCAP_PACKET_H
#define PCAP_PACKET_H
#include <arpa/inet.h>
/* ethernet headers are always exactly 14 bytes */
struct checksum_header{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t reserved = 0;
    uint8_t proto;
    uint16_t tcp_len;
};
struct ipv4_hdr{
         uint8_t ip_hl:4,      /* header length */
                ip_v:4;         /* version */
         uint8_t ip_tos;       /* type of service */
         uint16_t ip_len;         /* total length */
         uint16_t ip_id;          /* identification */
         uint16_t ip_off;
         uint8_t ip_ttl;          /* time to live */
         uint8_t ip_p;            /* protocol */
         uint16_t ip_sum;         /* checksum */
         uint32_t ip_src, ip_dst;
         //struct in_addr ip_src, ip_dst; /* source and dest address */
};
struct tcp_hdr{
    uint16_t th_sport;       /* source port */
         uint16_t th_dport;       /* destination port */
         uint32_t th_seq;          /* sequence number */
         uint32_t th_ack;          /* acknowledgement number */
         uint8_t  th_x2:4,         /* (unused) */
                  th_off:4;        /* data offset */
         uint8_t  th_flags;       /* control flags */
         uint16_t th_win;         /* window */
         uint16_t th_sum;         /* checksum */
         uint16_t th_urp;         /* urgent pointer */
};
#endif // PCAP_PACKET_H
