#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include "consts.h"
#include "dns.h"


#ifndef XDP 
    #define XDP_MAX_PAYLOAD_SIZE 101111
#endif

#ifndef xdp 
    #define XDP_FORWARD XDP_PASS
    #define XDP_DROP XDP_DROP
#endif

#define DEBUG_CONFIG_TYPE(X, ...) _Generic(X, \
    __U32:  bpf_printk("the config vvalue stored from map %u", X) \
    default: bpf_printk("the config vvalue stored from map %d", X)


struct xdp_actions {
    void (* parse_eth) (void *data, void *data_end);
};


SEC("xdp")
int xdp_process(struct xdp_md *ctx) {
    void *data = (void *)(long *) ctx->data;
    void *data_end = (void *)(long *) ctx->data_end;

    return XDP_PASS;
}

char __license[] SEC("license") = "MIT / GPL";

