#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <stdbool.h>

// libbpf 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "hdrs/dns.h"
#include "hdrs/consts.h"
#include "hdrs/utils.h" 
#include "hdrs/sockpin.h"

#define DEBUG false 

static 
__always_inline struct sock_proc_conn_info  __get_sock_proc_conn_info(__u16 dest_transport_port, struct __kernel_proc_struct_info *proc_info) {

    struct sock_proc_conn_info sock_proc_conn_info = (struct sock_proc_conn_info) {
        .pid = proc_info->procId,
        .threadId = proc_info->threadId,
        .dport = dest_transport_port
    };

    return sock_proc_conn_info;
}


static 
__always_inline void __update_egress_sock_proc_map(struct __sk_buff *skb, struct udphdr *udp) {
    __u16 src_transfer_port = bpf_ntohs(udp->source);
    __u16 dest_transport_port = bpf_ntohs(udp->dest);

    struct __kernel_proc_struct_info * proc_info = __get_process_info();
    
    if (dest_transport_port != DNS_EGRESS_PORT && dest_transport_port != DNS_EGRESS_MULTICAST_PORT && dest_transport_port != LLMNR_EGRESS_LOCAL_MULTICAST_PORT) {
            struct sock_proc_conn_info *curr_info = bpf_map_lookup_elem(&exfil_sock_udp_conn_map, &src_transfer_port);
            if (!curr_info) {
               // bpf_printk("the src port for transfer is %d", src_transfer_port);
                struct sock_proc_conn_info sock_proc_conn_info = __get_sock_proc_conn_info(dest_transport_port, proc_info);
                if (bpf_map_update_elem(&exfil_sock_udp_conn_map, &src_transfer_port, &sock_proc_conn_info, BPF_NOEXIST) < 0) {
                    #ifdef DEBUG 
                        if (DEBUG) {
                            bpf_printk("Error updating the udp sock map for transfer traffic"); 
                        }
                    #endif
                }
            }else {
             //   bpf_printk("the src port for transfer fd is  %d", src_transfer_port);

                if (curr_info->pid != proc_info->procId || curr_info->dport != dest_transport_port) {
                    struct sock_proc_conn_info sock_proc_conn_info = __get_sock_proc_conn_info(dest_transport_port, proc_info);
                    if (bpf_map_update_elem(&exfil_sock_udp_conn_map, &src_transfer_port, &sock_proc_conn_info, BPF_ANY) < 0) {
                        #ifdef DEBUG 
                            if (DEBUG) {
                                bpf_printk("Error updating the udp sock map for transfer traffic"); 
                            }
                        #endif
                    }
                }
        }
    }
}

// always update map for dns transfer over non standard port in kernel cgroup layer
static 
__always_inline bool __verify_udp_ports_diff_stand_dns(struct udphdr *udp) {
    __u16 dest_port = bpf_ntohs(udp->dest);
    return dest_port != DNS_EGRESS_PORT && 
           dest_port != DNS_EGRESS_MULTICAST_PORT && 
           dest_port != LLMNR_EGRESS_LOCAL_MULTICAST_PORT;
}

SEC("cgroup_skb/egress")
int dns_udp_sock_ops(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (verify_kernel_version_support_task_comm())
        return SK_PASS;

    // cgroup process for l3 with no raw l2 pack found in kernel stack over cgroup 
    // only process the udp frames for now over non standard DNS UDP ports
    // since the kernel tc does not support task the cgroup pin maps updates task_pid_tgid as it passes down kernel network stack to TC 
    switch (skb->family) {
        case AF_INET:  // IPv4 packets
            struct iphdr *iph = data;
            if ((void *)(iph + 1) > data_end) return SK_DROP; 

            if (iph->protocol == IPPROTO_UDP) { // UDP Pack 

                struct udphdr *udp = data + sizeof(struct iphdr);
                if ((void *)(udp + 1) > data_end) return SK_DROP; 

                if (__verify_udp_ports_diff_stand_dns(udp)) {
                    __update_egress_sock_proc_map(skb, udp);
                }
            }
        case AF_INET6: // IPv6 packets
            struct ipv6hdr *ip6h = data;
            if ((void *)(ip6h + 1) > data_end) return SK_DROP; 

            if (ip6h->nexthdr == IPPROTO_UDP) { 

                struct udphdr *udp = data + sizeof(struct ipv6hdr);
                if ((void *)(udp + 1) > data_end) return SK_DROP; 

                __u16 dest_port = bpf_ntohs(udp->dest); 

                if (__verify_udp_ports_diff_stand_dns(udp)) {
                    __update_egress_sock_proc_map(skb, udp);
                }
            }
        default:
            return SK_PASS; // not possible for a cgroup to receive 
    }
    return SK_PASS; 
}



char _license[] SEC("license") = "GPL";
