#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "consts.h"
#include "dns.h"


// only for egress traffic attachement 
SEC("tc") 
int classify(struct __sk_buff *skb){
    void *data = (void *)(ll)(skb->data);
    void *data_end = (void *)(ll)(skb->data_end);

    return TC_ACT_OK;
}


char __license[] SEC("license") = "MIT / GPL";
