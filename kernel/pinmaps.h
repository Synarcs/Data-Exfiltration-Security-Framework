#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>


struct exfil_security_egress_proc_mal {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // process id 
    __type(value, __u32);  // whether this process malicious transfer happened and all packets over this process must be dropped
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_egress_proc_mal SEC(".maps");