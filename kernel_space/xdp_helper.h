//
// Created by synarcs on 2/19/24.
//
#include <stdbool.h>
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>


#ifndef EBPF_HELPER_H
#define EBPF_HELPER_H

struct __xdp_payload {
    void *data;
    void *data_end;
};

static
__always_inline struct  __xdp_payload * get_xdp_pointers(struct xdp_md *skb){
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct __xdp_payload payload = {};
    payload.data_end = data_end;
    payload.data =data;
    return &payload;
}

static
__always_inline bool is_icmp_request(struct xdp_md *skb){

    struct __xdp_payload *payload = get_xdp_pointers(skb);
    struct ethhdr *eth = payload->data;

    if ((void *)eth + sizeof (*eth) > payload->data_end) return XDP_DROP;

}

static
__always_inline bool is_udp_request(struct xdp_md *skb){

}

static
__always_inline bool is_dns_request(struct xdp_md *skb){

}


#endif //EBPF_HELPER_H

