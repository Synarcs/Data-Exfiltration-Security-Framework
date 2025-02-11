#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h> 

#include "consts.h"
#include "utils.h"

#define EXFIL_SECURITY_PIN_DNS_EGRESS_PATH "/sys/fs/bpf/exfil_security_config_map"

#define NF_MAX_VERDICT NF_STOP

struct br_net_filter_config_map { 
    __u32 Bridge_if_index; // holds and process the if_index for bridge of linux ns 
    __u32  SKB_Mark;
}; 

struct exfil_security_tc_bridge_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // constant kernel key 
    __type(value, struct br_net_filter_config_map);   // layer ifindex for the kenrle bridge route;
    __uint(max_entries, 1);
} exfil_security_tc_bridge_config_map SEC(".maps");

// allow only traffic having the custom mark and stop any other packets over the bridge 
SEC("tc")
int bridge_ingress_filter(struct __sk_buff *skb) {
    // Add more context to your print
    __u32 out = skb->ifindex;
    __u32 mark = skb->mark;
    bpf_printk("Bridge TC: received packet on ifindex=%d mark=%u\n", 
            skb->ifindex, skb->mark);
 
    return TC_FORWARD;
}


char __license[] SEC("license") = "Dual MIT/GPL";

