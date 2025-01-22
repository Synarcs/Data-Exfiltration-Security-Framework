#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdbool.h> 

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4

#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define EXFIL_SECURITY_PIN_DNS_EGRESS_PATH "/sys/fs/bpf/exfil_security_config_map"

#define NF_MAX_VERDICT NF_STOP

__u32 redirect_skb_mark = 0xFF;
#define DEBUG true

struct br_net_filter_config_map { 
    __u32 Bridge_if_index; // holds and process the if_index for bridge of linux ns 
    __u32  SKB_Mark;
}; 

struct exfil_nf_bridge_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // constant kernel key 
    __type(value, struct br_net_filter_config_map);   // layer ifindex for the kenrle bridge route;
    __uint(max_entries, 1);
} exfil_nf_bridge_config_map SEC(".maps");

// only for ingress  process netfilter hooks over pre routing for ingress routing
// kernel for virtualized bridges dont have default qdisc and kernel queue classes to classify the packet in kernel
SEC("netfilter") 
int bridge_classify(struct bpf_nf_ctx *ctx){
    struct __sk_buff *skb = (struct  __sk_buff *)ctx->skb;

    __u32 out = skb->ifindex;

    __u32 br_index = 4; __u32 skb_mark = redirect_skb_mark;

    __u32 br_index_config_map_key = 0;

    struct br_net_filter_config_map * br_index_config_map_value = bpf_map_lookup_elem(&exfil_nf_bridge_config_map, &br_index_config_map_key); 
    if (br_index_config_map_value) {
        br_index = br_index_config_map_value->Bridge_if_index;
        skb_mark = br_index_config_map_value->SKB_Mark;
    }
    
    if (ctx->skb->skb_iif == br_index){
        bpf_printk("doing strick skb check since the packet redirected / cloned fro tc qdisc in kernel DPI");
        if (ctx->skb->mark == skb_mark) return NF_ACCEPT;
        else return NF_DROP;
    }

    // since netfilter is global allow all other net_devices traffic to flow over netfilter hooks  and chains 
    return NF_ACCEPT;
}

char __license[] SEC("license") = "GPL";

