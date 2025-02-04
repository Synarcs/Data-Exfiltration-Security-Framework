#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <stdbool.h>

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


#define MAX_DOMAIN_SIZE 255 


struct exfill_ingress_security_layer7_tld  {
    __uint(type ,BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // dns query
    __type(value, __u8); // boolean flag for user space to understand if the id is in map it need ingress DPI based on tld or other factor 
    __uint(max_entries, 1 << 12);
} exfil_security_detected_c2c_tld SEC(".maos");

struct xdp_parse {
    __u8 (*parse_dns_header) (void * ,struct __sk_buff *, bool, bool);
};

struct cursosr {
    void *data;
    void *data_end;
}   __attribute__((packed)) xdp_cursor;


static 
__always_inline __u8 __parse_dns_header_content(struct dns_header *dns, struct __sk_buff *skb) {

    struct dns_flags flags =  get_dns_flags(dns);
    return 1;
}

/*
    The XDP only porcess over the ingress dns traffic from kernel over rx queue for the device driver inside kernel 
*/
SEC("xdp")
int xdp_process(struct xdp_md *ctx) {
    void *data = (void *)(__u32 *) ctx->data;
    void *data_end = (void *)(__u32 *) ctx->data_end;

    __u32 ifIndex = ctx->ingress_ifindex;

    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) return XDP_DROP;

    switch (eth->h_proto) {
        case bpf_ntohs(ETH_P_IP): {

            struct iphdr *ip = (struct iphdr *)(eth + 1);
            if ((void *) (ip + 1) > data_end) return XDP_DROP;

            switch (ip->protocol) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)((void *) ip + sizeof(struct iphdr));
                    if ((void *) (udp + sizeof(struct udphdr)) > data_end) return XDP_DROP;

                    if (udp->dest == bpf_ntohs(DNS_EGRESS_PORT)) {
                        __u32 payload_len = udp->len;
                        if (sizeof(struct dns_header) > payload_len) return XDP_DROP;
                        return XDP_PASS;
                    }else if (udp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)) return XDP_PASS;
                    struct dns_header *dns = (struct dns_header *)((void *) udp + sizeof(struct udphdr));
                    return XDP_PASS;
                }
                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)((void *) ip + sizeof(struct iphdr));
                    if ((void *) (tcp + sizeof(struct tcphdr)) > data_end) return XDP_DROP;

                    if (tcp->dest == bpf_ntohs(DNS_EGRESS_PORT)){
                        struct dns_header *dns = (struct dns_header *)((void *) tcp + sizeof(struct udphdr));
                        return XDP_PASS;
                    }
                }
                default: { return XDP_PASS; }
            }
            break;
        }
        case bpf_ntohs(ETH_P_IPV6): {
            struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);
            if ((void *) (ip + 1) > data_end) return XDP_DROP;

            switch (ip->nexthdr) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)(ip + sizeof(struct ipv6hdr));
                    if ((void *) (udp + sizeof(struct udphdr)) > data_end) return XDP_DROP;
                    
                    struct dns_header *dns = (struct dns_header *)((void *) udp + sizeof(struct udphdr));
                    return XDP_PASS;
                }
                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)(ip + sizeof(struct ipv6hdr));

                    struct dns_header *dns = (struct dns_header *)((void *) tcp + sizeof(struct udphdr));

                    if ((void *) (tcp + sizeof(struct tcphdr)) > (void *) data_end) return XDP_DROP;

                    return XDP_PASS;
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

