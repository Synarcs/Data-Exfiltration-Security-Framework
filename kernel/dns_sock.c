#include <linux/bpf.h>
#include <linux/kernel.h>

#include <linux/ip.h>
// l2 filter in kerenl 
#include <linux/if_ether.h>

// l3 dynamic sock filter
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
// l4 dynamic sock filter 
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "dns.h"
#include "consts.h"
#include "utils.h"
#include "raw_proc.h"

#ifndef tc
    #define TC_FORWARD TC_ACT_OK
    #define TC_DEFAULT TC_ACT_UNSPEC
    #define TC_DROP TC_ACT_SHOT
#endif

// kernel skb packet offsets 
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CHECK_FF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_CHECK_FF_V6 (ETH_HLEN + offsetof(struct ipv6hdr, check))

#define UDP_CHECK_FF (ETH_HLEN + offsetof(struct udphdr, check))
#define TCP_CHECK_FF (ETH_HLEN + offsetof(struct tcphdr, check))

struct enabled_exfil_netPol_config { 
    __u8 l3_filter;
    __u8 l4_filter; // l4 filter only applies if the required l3 matches 
};

struct exfil_security_egress_netpool_filter {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u8);
    __type(value, struct enabled_exfil_netPol_config);
    __uint(max_entries, 1); 
} exfil_security_egress_netpool_filter SEC(".maps");

// TODO: Add support for ipv6 support over filter 
struct enabled_exfil_netPol_config_malicious_c2_address { 
    __be32 ipv4_address; // inherit support user space ensure convert to network order 
    __u16 port;
};

// user space will populate sockets which runs the mutation and inference server where sock are redirected for deep scan from kernel 
struct exfil_security_egress_sock_redirect_map_dpi {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct enabled_exfil_netPol_config_malicious_c2_address);
    __uint(max_entries, 1 << 4); // only 4 for custom sock hold by the socket layer 
} exfil_security_egress_sock_redirect_map_dpi SEC(".maps");


// the security will be enforeced over kernel tc  post noqueue best packet deleiver 
// the rason for not operation over sock ops in kernel, is this may interfere with other CNI sock and their associated maps used, for example cilium manages all this maps over kernel sock layer filter, lb, routing via cilium controller on host 
SEC("tc")
int process(struct __sk_buff *skb) {

    const __u8 tc_config_key = 0;
    bool l3_filter = false, l4_filter = false;
    struct enabled_exfil_netPol_config *redir_config = bpf_map_lookup_elem(&exfil_security_egress_sock_redirect_map_dpi, &tc_config_key);
    if (!redir_config) 
        return TC_FORWARD;
    else {
        if (redir_config->l3_filter) 
            l3_filter = true;
        if (redir_config->l4_filter) 
            l4_filter = true;
    }

    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 

    void *data = (void *)(ull)skb->data;
    void *data_end = (void *)(ull)skb->data_end;

    // parse the raw skb upto l4, and l7 for only dns traffic filter 
    // the kernel sock virtualized cni bridge dont need l7 filter since if the malicious c2 passes through host for dNS resolution forwarded through coredns the host bridge k8s tc  eBPF node agent will kill it 
    // this dynamic filter ensure dynamic killing of l3 traffic malicious ips

    struct ethhdr *eth = (struct ethhdr *) data;
    if ((void *)(eth + 1) > skb->data_end) return TC_DROP;
    
    // no vlan overlay encap inside pod 
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *) eth;
        if ((void *)(ip + 1) > skb->data_end) return TC_DROP;
        struct enabled_exfil_netPol_config_malicious_c2_address *ip_config_filter;
        if (l3_filter) {
            ip_config_filter = bpf_map_lookup_elem(&exfil_security_egress_sock_redirect_map_dpi, &ip->daddr);
            if (ip_config_filter)
                return TC_DROP;
        }

        if (l4_filter) {
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *) (ip);
                if ((void *) (udp + 1) > skb->data_end) return TC_DROP;
                if (ip_config_filter && ip_config_filter->port == bpf_ntohs(udp->dest) &&
                             ip->daddr == ip_config_filter->ipv4_address)
                    return TC_DROP;
                return TC_FORWARD;
            }if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *) (ip);
                if ((void *) (tcp + 1) > skb->data_end) return TC_DROP;
                if (ip_config_filter && ip_config_filter->port == bpf_ntohs(tcp->dest) && 
                                ip->daddr == ip_config_filter->ipv4_address)
                    return TC_DROP;
                return TC_FORWARD;
            }
        }

        return TC_FORWARD;
    }if (eth->h_proto == bpf_htons(ETH_P_IPV6)){
        return TC_FORWARD;
    }

    return TC_FORWARD;
}


char __license[] SEC("license") = "MIT/GPL"; 