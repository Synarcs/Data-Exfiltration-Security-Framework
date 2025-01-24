#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "dns.h"
#include "consts.h"
#include "utils.h"
#include "raw_proc.h"


// user space will populate sockets which runs the mutation and inference server where sock are redirected for deep scan from kernel 
struct exfil_security_egress_sock_redirect_map_dpi {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, 1 << 4); // only 4 for custom sock hold by the socket layer 
} exfil_security_egress_sock_redirect_map_dpi SEC(".maps");


SEC("sock")
int process(struct __sk_buff *skb) {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 


    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end; 


    const  __u32 ipc_pod_container_redirect_sockkey = 9;
    return bpf_sk_redirect_map(skb, &exfil_security_egress_sock_redirect_map_dpi, &ipc_pod_container_redirect_sockkey, BPF_ANY);
}


char __license[] SEC("license") = "MIT/GPL"; 