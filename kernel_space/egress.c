
//

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/types.h>

//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>

#include "dns_xdp_skb_helpers.h";


int egress_handler(struct __sk_buff *skb){
    void *data = (void *)(long ) skb->data;
    void *data_end = (void *) (long ) skb->data_end;

    if (bpf_htons(skb->protocol) == IPPROTO_ICMP)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}


