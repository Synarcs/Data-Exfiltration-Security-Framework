//
// Created by synarcs on 2/26/24.
//

#ifndef C1_SKB_HELPERS_H
#define C1_SKB_HELPERS_H

#endif //C1_SKB_HELPERS_H

#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/pkt_cls.h>

#include "header.h"
#include "init.h"
#include "xdp_helper.h"

// debug purpose
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct skb_event {
    int eventId;
    char eventName[100];
};

static __always_inline struct ethhdr * handler(struct __sk_buff *skbuff) {
    void *data = (void *)(long)skbuff->data;
    void *data_end = (void *)(long)skbuff->data_end;
    struct skb_event event = {};
    bpf_probe_read_kernel(sizeof (struct skb_event), &event);

    u64 protocol = bpf_ntohs(skbuff->protocol);
    return (struct ethhdr *) data;
}

static __always_inline struct dns_query_section * get_query_section(struct dns_header *dnsHeader){
    return NULL;
}

static __always_inline struct dns_answer_section * dns_answer_section(struct dns_header *dnsHeader){
    return NULL;
}




