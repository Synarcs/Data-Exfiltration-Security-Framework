#include <linux/bpf.h>

#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#include "consts.h"
#include "dns.h"


#ifndef tc
    #define TC_FORWARD TC_ACT_OK
    #define TC_DEFAULT TC_ACT_UNSPEC
    #define TC_DROP TC_ACT_SHOT
#endif

SEC("tc")
int classify(struct __sk_buff *skb){    
    void *data = (void *)(ll)(skb->data);
    void *data_end = (void*)(ll)(skb->data_end);


    // do packet parsing only for encapsulation header vxlan and bridges 
    struct ethhdr *eth = (struct ethhdr *) data;
    
    return TC_DROP;
}
