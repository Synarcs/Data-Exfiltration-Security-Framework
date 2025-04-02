#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "consts.h"

struct kill_proc_mal_payload {
    __u32 MalDetectedCount;
    __u32 dest_port;
};

struct exfil_security_egress_proc_mal {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // process id 
    __type(value, struct kill_proc_mal_payload);  // whether this process malicious transfer happened and all packets over this process must be dropped
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_egress_proc_mal SEC(".maps");


struct exfil_security_egress_nsp_map_key {
    __u32 processId;
    __u16 dport;
};

struct exfil_security_egress_nsp_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, struct exfil_security_egress_nsp_map_key); // dport, procId count malicious transfer over the unqieu key fd detected from user space added in kernel over first transfer
    __type(value, __u32); // detected malicious count of packets on the dport
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_egress_nsp_map SEC(".maps");



// dynamic netpool l3 ipv4 filtering for any malicious traffic found to upstream servers 
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    struct exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 1 << 10);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    } exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter SEC(".maps");
#endif 


#if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    struct exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct in6_addr);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 1 << 10);
    } exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter SEC(".maps");
#endif 