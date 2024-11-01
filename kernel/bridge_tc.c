#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdbool.h>
#include "consts.h"
#include "dns.h"

static 
__always_inline bool __verify_tc_dpi_ingress_process(struct __sk_buff *skb) {
    if (skb->mark != bpf_ntohs(redirect_skb_mark)) {
        #ifdef DEBUG 
            if (!DEBUG) bpf_printk("dropping the packet the packet is not created by parent host redirect in kernel tc layer");
        #endif  
        return false;
    }
    return true;
}

// only for egress traffic attachement 
SEC("tc") 
int classify(struct __sk_buff *skb){
    void *data = (void *)(ll)(skb->data);
    void *data_end = (void *)(ll)(skb->data_end);

    if (!__verify_tc_dpi_ingress_process(skb)) return TC_ACT_SHOT;
    return TC_ACT_OK;
}




char __license[] SEC("license") = "MIT / GPL";
