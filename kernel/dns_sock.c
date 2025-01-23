#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "dns.h"
#include "consts.h"
#include "utils.h"
#include "raw_proc.h"


struct exfil_security_egress_sock_map_dpi {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, 1 << 4); // only 4 for custom sock hold by the socket layer 
} exfil_security_egress_sock_map_dpi SEC(".maps");


SEC("sock")
int process(struct __sk_buff *skb) {
    
}


char __license[] SEC("license") = "MIT/GPL"; 