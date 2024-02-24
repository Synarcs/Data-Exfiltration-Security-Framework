#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "header.h"

static __always_inline struct iphdr * is_ip_header(void *data,
                    void *data_end){
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return NULL;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return NULL;

    return iph;
}

static __always_inline struct icmphdr * is_icmp_layer3(void *data,
                                                           void *data_end) {

    struct iphdr *iph = is_ip_header(data, data_end);
    if (!iph) return NULL;

    if (iph->protocol != IPPROTO_ICMP)
        // We're only interested in ICMP packets
        return NULL;

    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
        sizeof(struct icmphdr) > data_end)
        return NULL;

    return icmp;
}


static __always_inline struct tcphdr * is_tcp_header(void *data, void *data_end){
    struct iphdr *iph = is_ip_header(data, data_end);
    if (!iph) return NULL;

    struct tcphdr *tcp_header = data + sizeof (struct  ethhdr) +
                                sizeof (struct iphdr) + sizeof (struct tcphdr);
    if (data + sizeof (struct ethhdr) + sizeof (struct  iphdr)
                                        + sizeof (struct tcphdr) > data_end)
        return NULL;

    return tcp_header;
}

static __always_inline struct tcphdr * is_udp_header(void *data, void *data_end){
    struct iphdr *iph = is_ip_header(data, data_end);
    if (!iph) return NULL;

    struct udphdr *udp_header = data + sizeof (struct  ethhdr) +
                                sizeof (struct iphdr) + sizeof (struct udphdr);
    if (data + sizeof (struct ethhdr) + sizeof (struct  iphdr)
        + sizeof (struct udphdr) > data_end)
        return NULL;

    return udp_header;
}

static __always_inline unsigned short is_dns(void *data, void *data_end){

    struct udphdr *udp_header = is_udp_header(data, data_end);
    if (!udp_header) return NULL;

    return 0;
}