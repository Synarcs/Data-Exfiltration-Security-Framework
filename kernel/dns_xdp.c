#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "consts.h"
#include "dns.h"
#include "utils.h"

#ifndef XDP 
    #define XDP_MAX_PAYLOAD_SIZE 101111
#endif


#define DEBUG_CONFIG_TYPE(X, ...) _Generic(X, \
    __U32:  bpf_printk("the config vvalue stored from map %u", X) \
    default: bpf_printk("the config vvalue stored from map %d", X)


struct exfil_security_ingress_drop_ring_buff {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exfil_security_egress_drop_ring_buff SEC(".maps");

struct cursosr {
    void *data;
    void *data_end;
}   __attribute__((packed)) xdp_cursor;

struct xdp_actions {
    void (* parse_eth) (void *data, void *data_end);
};

SEC("xdp")
int xdp_process(struct xdp_md *ctx) {
    void *data = (void *)(long *) ctx->data;
    void *data_end = (void *)(long *) ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) return XDP_DROP;

    switch (eth->h_proto) {
        case bpf_ntohs(ETH_P_IP): {

            struct iphdr *ip = eth;
            if ((void *) (ip + 1) > data_end) return XDP_DROP;

            switch (ip->protocol) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = ip;
                    if ((void *) (udp + 1) > data_end) return XDP_DROP;
                    break;
                }
                case IPPROTO_TCP: {
                    struct tcphdr *tcp = ip;
                    if ((void *) (tcp + 1) > data_end) return XDP_DROP;
                    break;
                }
                default: { return XDP_PASS; }
            }
            break;
        }
        case bpf_ntohs(ETH_P_IPV6): {
            struct ipv6hdr *ip = eth;
            if ((void *) (ip + 1) > data_end) return XDP_DROP;

            switch (ip->nexthdr) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = ip;
                    if ((void *) (udp + 1) > data_end) return XDP_DROP;
                    break;
                } 

                case IPPROTO_TCP: {
                    struct tcphdr *tcp = ip; 
                    if ((void *) (tcp + 1) > (void *) data_end) return XDP_DROP;
                }
            }
            break;
        }
        default: 
            return XDP_PASS;
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "MIT / GPL";

