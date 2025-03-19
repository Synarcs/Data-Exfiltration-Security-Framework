#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#define MAX_SOCK_OPT_UDP_SOCK_DNS 10240 


struct udp_sock_conn_info {
    __u32 pid;
    __u32 threadId;
    __u32 userId;
    __u32 groupId;
    __u16 dport;
    char comm[MAX_PROC_COMM_SIZE];       // TASK_COMM_PROC_INFO 
};


struct exfil_sock_udp_conn_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16); // kernel enforced security for l3 TC can extract easily from raw skb  in kernel TC layer 
    __type(value, struct udp_sock_conn_info);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // will be shared throught the kernel TC layer lower on NIC once packet forwards from netfilter
} exfil_sock_udp_conn_map SEC(".maps");
