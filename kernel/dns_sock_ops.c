#include <linux/udp.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/types.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include <stdbool.h>

// libbpf 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "sockpin.h"
#include "consts.h"
#include "utils.h"
#include "dns.h"


#define DEBUG false 

static 
__always_inline void __update_egress_sock_proc_map(struct __sk_buff *skb, struct udphdr *udp) {
    __u16 src_transfer_port = bpf_ntohs(udp->source);
    __u16 dest_transport_port = bpf_ntohs(udp->dest);
    
    struct __kernel_proc_struct_info * proc_info = __get_process_info();

    if (dest_transport_port != DNS_EGRESS_PORT && dest_transport_port != DNS_EGRESS_MULTICAST_PORT && dest_transport_port != LLMNR_EGRESS_LOCAL_MULTICAST_PORT) {
            struct sock_proc_conn_info *curr_info = bpf_map_lookup_elem(&exfil_sock_udp_conn_map, &src_transfer_port);
            if (!curr_info) {
                bpf_printk("the src port for transfer is %d", src_transfer_port);
                struct sock_proc_conn_info sock_proc_conn_info = (struct sock_proc_conn_info) {
                    .pid = proc_info->procId,
                    .threadId = proc_info->threadId,
                    .dport = dest_transport_port
                };
                if (bpf_map_update_elem(&exfil_sock_udp_conn_map, &src_transfer_port, &sock_proc_conn_info, BPF_ANY) < 0) {
                    #ifdef DEBUG 
                        if (DEBUG) {
                            bpf_printk("Error updating the udp sock map for transfer traffic"); 
                        }
                    #endif
                }
            }else {
                bpf_printk("the src port for transfer fd is  %d", src_transfer_port);

                if (curr_info->pid != proc_info || curr_info->dport != dest_transport_port) {
                    struct sock_proc_conn_info sock_proc_conn_info = (struct sock_proc_conn_info) {
                        .pid = proc_info->procId,
                        .threadId = proc_info->threadId,
                        .dport = dest_transport_port
                    };
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

SEC("cgroup_skb/egress")
int dns_udp_sock_ops(struct __sk_buff *skb) {
    
    if (verify_kernel_version_support_task_comm()) 
        return 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return 1; // Allow packet, can't parse
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        bpf_printk("IPv4 packet found for egress");
        
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return 1; // Allow packet, can't parse
        }
        
        if (ip->protocol == IPPROTO_UDP) {
            bpf_printk("UDP packet found for egress");
            
            void *transport_header = (void *)ip + (ip->ihl * 4);
            
            struct udphdr *udp = transport_header;
            if ((void *)(udp + 1) > data_end) {
                return 1; // Allow packet, can't parse
            }
            
            __u16 dest_port = bpf_ntohs(udp->dest);
            bpf_printk("UDP dest port: %d", dest_port);
            __update_egress_sock_proc_map(skb, udp);
        }
    } 
    // Process IPv6 packets
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("IPv6 packet found for egress");
        
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            return 1; // Allow packet, can't parse
        }
        
        if (ip6->nexthdr == IPPROTO_UDP) {
            bpf_printk("UDP packet found for egress (IPv6)");
            
            void *transport_header = (void *)ip6 + sizeof(*ip6);
            
            struct udphdr *udp = transport_header;
            if ((void *)(udp + 1) > data_end) {
                return 1;
            }
            
            __u16 dest_port = bpf_ntohs(udp->dest);
            bpf_printk("UDP dest port (IPv6): %d", dest_port);
            __update_egress_sock_proc_map(skb, udp);
        }
    }
    return 1;
}

char _license[] SEC("license") = "GPL";