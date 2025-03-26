// <!---------------------------
// Name: DNSObelisk
// File: bridge_tc_ing.c
// -----------------------------
// Author: Synarcs
// ---------------------------->

#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h> 

#include "hdrs/consts.h"
#include "hdrs/utils.h" 
#include "hdrs/dns.h"
#include "hdrs/raw_proc.h"

#define EXFIL_SECURITY_PIN_DNS_EGRESS_PATH "/sys/fs/cbpf/exfil_security_config_map"

struct exfil_security_tc_bridge_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // constant kernel key 
    __type(value, __u32);   // layer ifindex for the kenrle bridge route;
    __uint(max_entries, 1);
} exfil_security_tc_bridge_config_map SEC(".maps");

// allow only traffic having the custom mark and stop any other packets over the bridge 
SEC("tc")
int bridge_ingress_filter(struct __sk_buff *skb) {
    // Add more context to your print
    __u32 out = skb->ifindex;
    __u32 mark = skb->mark;

    #ifdef DEBUG
        if (DEBUG) {
            bpf_printk("Bridge TC: received packet on ifindex=%d mark=%u\n", 
                skb->ifindex, skb->mark);
        }
    #endif

    // TODO: Fix the node agent kernel random map for sk_buff guard work 
    __u32 skb_mark_key = 0;
    __u32 * skb_hash = bpf_map_lookup_elem(&exfil_security_tc_bridge_config_map, &skb_mark_key);
    if (!skb_hash) {
        if (skb->mark != redirect_skb_mark)  {
            return bpf_redirect(0, BPF_F_INGRESS); // lo service loopback a dead end loop for egress kenrel gc over the rx queue for the packet 
        }
    }else {
        if (skb->mark != *skb_hash)  {
            return bpf_redirect(0, BPF_F_INGRESS); // lo service loopback a dead end loop for egress kenrel gc over the rx queue for the packet 
        }
        return TC_FORWARD;
    }
}


char __license[] SEC("license") = "Dual MIT/GPL";

