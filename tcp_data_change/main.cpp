#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <map>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <arpa/inet.h>

#include "TCPDataChange.h"
#include "typekey.h"
using namespace std;

string fromString;
string toString;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}
typedef pair<uint32_t, uint16_t> ip_port;
static int cb(struct nfq_q_handle *qhandle, struct nfgenmsg *nfmsg,
                    struct nfq_data *nf_data, void *data)
{

    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet;
    unsigned char *changed_data;
    u_int32_t id=0;
    int len;


    if((ph = nfq_get_msg_packet_hdr(nf_data)))
        id = ntohl(ph->packet_id);

    len = nfq_get_payload(nf_data,&packet);
    if(len)
    {
        changed_data = packet;

        struct ipv4_hdr *ip;
        struct tcp_hdr *tcp;

        ip = (struct ipv4_hdr *)packet;
        packet += sizeof(struct ipv4_hdr);
        tcp = (struct tcp_hdr *)packet;



        // tcp && ipv4
        if((ip->ip_p == 0x6) && (ntohs(tcp->th_sport) == 80))
        {


            map<TcpFlowkey ,uint32_t> kv;

            TcpFlowkey tcpkey;
            tcpkey.srcIp = ip->ip_src;
            tcpkey.srcPort = tcp->th_sport;
            tcpkey.dstIp = ip->ip_dst;
            tcpkey.dstPort = tcp->th_dport;

            packet += sizeof(struct tcp_hdr);

            uint16_t size_ip_tcp = (ip->ip_hl * 4) + (tcp->th_off * 4);

            // replace string
            string tmp_data = (char *)packet;
            string before = (char *)packet;
            tmp_data = replaceString(tmp_data, fromString, toString);
            string after = tmp_data;
            u_int16_t changedLen = after.size() - before.size();


            char *tmp = new char[tmp_data.length() + 1];
            struct ipv4_hdr *tmp_ip;
            struct tcp_hdr *tmp_tcp;

            strcpy(tmp, tmp_data.data());
            tmp_ip = (struct ipv4_hdr*)tmp;
            tmp_tcp = (struct tcp_hdr*)(tmp + sizeof(struct ipv4_hdr));

            if(changedLen){// if len changed
                kv.insert(make_pair(tcpkey,changedLen));
            }

            //if same key
            if(kv.find(tcpkey.reverse()) != kv.end()){
                tmp_tcp->th_ack -= kv[tcpkey];
            }
            if(kv.find(tcpkey) != kv.end()){
                   tmp_tcp->th_seq += kv[tcpkey];
            }

            // change data
            memcpy((changed_data + size_ip_tcp), tmp, (len - size_ip_tcp));

            // calc checksum
            checksum(changed_data, len);

            return nfq_set_verdict(qhandle, id, NF_ACCEPT, len, changed_data);
        }
        else
            return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
    }
}
void usage() {
  printf("syntax: tcp_data_change <from string> <to string>\n");
  printf("sample: tcp_data_change hacking HOOKING\n");
}
int main(int argc, char **argv)
{

    if(argc != 3){
        usage();
        return -1;
    }

    fromString = argv[1];
    toString = argv[2];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);


    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

