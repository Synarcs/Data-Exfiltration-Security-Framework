// <!---------------------------
// Name: Data Exfiltration Security Framework
// File: dns_tc.c
// -----------------------------
// Author: Synarcs
// Data:   10/25/2024, 2:59:15 AM
// ---------------------------->

#include <linux/bpf.h>

#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdbool.h>
#include <signal.h>

#include "consts.h"
#include "dns.h"


#ifndef tc
    #define TC_FORWARD TC_ACT_OK
    #define TC_DEFAULT TC_ACT_UNSPEC
    #define TC_DROP TC_ACT_SHOT
#endif

// map storing the kernel information which hold if a dns packet or layer 7 packet is found to be tranfered over 
// the kernel tunnel tranfer driver 
struct exfil_tunnel_dns_encap_transfer {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1 << 10); // keep thhis minimum for potential kill threshold and packet drop trying to bind this map 
} exfil_tunnel_dns_encap_transfer SEC(".maps");

typedef struct ProcessEvent {
    __u32 buffer;
} proc;

#define MAX_TUNNEL_TUN_TAP_TRANSFER_THRESHOLD 100 

static 
__always_inline bool __inc_tunnel_packet_transfer() {
    __u32 TUNNEL_METRIC_KEY = 0;
    __u32 * tunnel_layer7_dns_count = bpf_map_lookup_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY);
    if (tunnel_layer7_dns_count) {
        if (*tunnel_layer7_dns_count >= MAX_TUNNEL_TUN_TAP_TRANSFER_THRESHOLD) {
            __u32 reset_kernel_packet_value = 0;
            if (bpf_map_update_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY, &reset_kernel_packet_value, 0) < 0) {
                #ifdef DEBUG
                    if (DEBUG) {
                        bpf_printk("error resset the egress filter for the kernel packet drops with SIGKILL to parent process");
                    }
                #endif 
            }
            return 1; // the process will be killed with SIGKILL REINT THE SOCKET OR FILTER TO POTENTIALLY KILL THE PROCESS 
        }
        __sync_fetch_and_add(tunnel_layer7_dns_count, 1); // atomic inc in kernel memory 
    }else {
        __u32 init_tunnel_count = 1;
        bpf_map_update_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY, &init_tunnel_count, 0);
    }

    return 0;
}

SEC("tc")
int classify(struct __sk_buff *skb){    
    void *data = (void *)(ll)(skb->data);
    void *data_end = (void*)(ll)(skb->data_end);

    // do packet parsing only for encapsulation header vxlan and bridges 
    // the tuntap interface should not be used for transfer and any potential packet encapsualtion 
    __u32 ifIndex = skb->ifindex;

    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) return XDP_DROP;

    switch (eth->h_proto) {
        case bpf_ntohs(ETH_P_IP): {

            struct iphdr *ip = (struct iphdr *)(eth + 1);
            if ((void *) (ip + 1) > data_end) return TC_DROP;

            switch (ip->protocol) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)((void *) ip + sizeof(struct iphdr));
                    if ((void *) (udp + sizeof(struct udphdr)) > data_end) return TC_DROP;

                    if (udp->dest == bpf_ntohs(DNS_EGRESS_PORT) || udp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)) {
                        // a potential dns packet for layer 7 app  transfer onto the egress wire 
                        if (__inc_tunnel_packet_transfer()) {
                            // pin map to kprobe or tracepoint before pre sock maps to drop the pakcet in kernel itself 
                            return TC_DROP;
                        }
                    } // todo DPI for non started egress port is not possible for post transfer 
                    return TC_FORWARD;
                }
                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)((void *) ip + sizeof(struct iphdr));
                    if ((void *) (tcp + sizeof(struct tcphdr)) > data_end) return TC_DROP;


                    if (tcp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)  || tcp->dest == bpf_ntohs(DNS_EGRESS_PORT)){
                        if (__inc_tunnel_packet_transfer()) return TC_DROP;
                    }
                    return TC_FORWARD;
                }
                default: { return TC_FORWARD; }
            }
            break;
        }
        case bpf_ntohs(ETH_P_IPV6): {
            struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);
            if ((void *) (ip + 1) > data_end) return XDP_DROP;

            switch (ip->nexthdr) {
                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)(ip + sizeof(struct ipv6hdr));
                    if ((void *) (udp + sizeof(struct udphdr)) > data_end) return TC_DROP;
                    
                    if (udp->dest == bpf_ntohs(DNS_EGRESS_PORT) || udp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)) {
                        // a potential dns packet for layer 7 app  transfer onto the egress wire 
                        if (__inc_tunnel_packet_transfer()) return TC_DROP;
                    }// todo DPI for non started egress port is not possible for post transfer 
                    // __sync_fetch_and_add()

                    return TC_FORWARD;
                }
                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)(ip + sizeof(struct ipv6hdr));
                    if ((void *) (tcp + sizeof(struct tcphdr)) > data_end) return TC_DROP;

                    if (tcp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)  || tcp->dest == bpf_ntohs(DNS_EGRESS_PORT)){
                        if (__inc_tunnel_packet_transfer()) return TC_DROP;
                    }

                    return TC_FORWARD;
                }
            }
            break;
        }
        default: 
            return XDP_PASS;
    }
    return TC_DROP;
}
