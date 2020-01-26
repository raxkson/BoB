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
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include "pcap_packet.h"
#include "IPchange.h"
//#include "TCPDataChange.h"
#include "typekey.h"
using namespace std;
string spoofingIp;
string getServerIP()
{
    char myip[20];
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int kDnsPort = 53;

    struct sockaddr_in serv;
    struct sockaddr_in host_name;

    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(kDnsPort);

    if( connect(sockfd, (struct sockaddr *)&serv, sizeof(serv)) < 0 ) printf("[-] sock connect for get ipaddr faild!\n");

    socklen_t host_len = sizeof(host_name);
    if( getsockname(sockfd, (struct sockaddr *)&host_name, &host_len) < 0 ) printf("[-] getsockname faild!\n");

    inet_ntop(AF_INET, &host_name.sin_addr, myip, sizeof(myip));
    close(sockfd);

    //printf("my ip : %s\n", myip);
    return (const char*)myip;
}
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
    u_int32_t id=0;
    int len;

    if((ph = nfq_get_msg_packet_hdr(nf_data)))
        id = ntohl(ph->packet_id);

    len = nfq_get_payload(nf_data,&packet);
    if(len)
    {

        struct ipv4_hdr *ip;
        struct tcp_hdr *tcp;

        ip = (struct ipv4_hdr *)packet;
        tcp = (struct tcp_hdr *)(packet + sizeof(struct ipv4_hdr));

        u_int32_t changed_ip = inet_addr(spoofingIp.c_str());

        //get my ip
        const char* myip = reinterpret_cast<const char *>(getServerIP().c_str());
        u_int32_t myip_int = inet_addr(myip);

        map<IPFlowkey, IPFlowkey>kv;
        IPFlowkey ipKey(ip->ip_dst, tcp->th_dport);
        IPFlowkey tmpKey(changed_ip, tcp->th_dport);
        // tcp && ipv4
        if((ip->ip_p == 0x6))
        {
            //outbound
            if(myip_int == ip->ip_src){
                //change dst ip
                // i change ip_dst to changed_ip
                // u have to memory
                 if(kv.find(ipKey) != kv.end()){
                     ip->ip_dst = changed_ip;
                     //tcp->th_dport = changed_port;
                     kv.insert(make_pair(ipKey,tmpKey));
                 }else{
                     ip->ip_dst = changed_ip;
                     //tcp->th_dport = changed_port;
                 }
            }
            //inbound
            IPFlowkey srcKey(ip->ip_src, tcp->th_sport);

            if(myip_int == ip->ip_dst){
                for(auto it = kv.begin(); it != kv.end(); ++it){
                    if(it->second == tmpKey){
                        ip->ip_src = it->first.ip_;
                        tcp->th_sport = it->first.port_;
                    }
                }
            }

            //calc checksum
            IPChecksum((uint8_t*)ip);

            return nfq_set_verdict(qhandle, id, NF_ACCEPT, len, packet);
        }
        else
            return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
    }
}
void usage() {
  printf("syntax: ip_change <dst_ip>\n");
  printf("sample: ip_change 192.168.10.2\n");
}
int main(int argc, char **argv)
{

    if(argc != 2){
        usage();
        return -1;
    }
    spoofingIp = argv[1];

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

