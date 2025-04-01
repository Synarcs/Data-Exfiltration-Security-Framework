/* Copyright (c) 2024-2025 Synarcs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *   -----------------------------
 *    Author: Synarcs
 *    Data:   09/25/2024, 2:59:15 AM
 *   -----------------------------
*/

#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_packet.h> // AF_PACKET raw kernel sock 
#include <linux/if_tun.h> // for TUN_TAP tunnel packet link 
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

// libbpf
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "hdrs/dns.h"
#include "hdrs/consts.h"
#include "hdrs/utils.h" 
#include "hdrs/raw_proc.h"
#include "hdrs/vxlan.h"
#include "hdrs/pinmaps.h"
#include "hdrs/sockpin.h"
#include "hdrs/rlt.h" // ratelimiter over kernel TC 

#define SIZE_INFO(ptr, data, end) \
    if ((void *) ptr + sizeof(data) > end) return TC_ACT_SHOT;


#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_CHECK_FF (ETH_HLEN + offsetof(struct iphdr, check))

#define IP_CHECK_FF_V6 (ETH_HLEN + offsetof(struct ipv6hdr, check))

#define UDP_CHECK_FF (ETH_HLEN + offsetof(struct udphdr, check))
#define TCP_CHECK_FF (ETH_HLEN + offsetof(struct tcphdr, check))

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF


// actions used to parse the all layers of kernel network stack from skb 
struct packet_actions {
    // init the cursror to hold packet cursor information from skb 
    void (*cursor_init) (struct skb_cursor *, struct __sk_buff *);
    // init all the fuctionr ref pointers to parse each layer of kernel network stack raw from skb 
    struct packet_actions (*packet_class_action) (struct packet_actions actions);
    // link layer
    __u8 (*parse_eth) (struct skb_cursor *);
    // router layer 3
    __u8 (*parse_ipv4) (struct skb_cursor *);
    __u8 (*parse_ipv6) (struct skb_cursor *);
    // transport layer 4 
    __u8 (*parse_udp) (struct skb_cursor *, bool);
    __u8 (*parse_tcp) (struct skb_cursor *, bool);
    /* 
        Each layer 4 parsing overthe header is processed with the previous layer header size offset 
    */
    
    // app layer 
    __u8 (*parse_dns_header_size) (struct skb_cursor *, bool, bool);
    __u8 (*parse_dns_payload_transport_udp) (struct skb_cursor *, void *, __u32, __u32,  struct dns_header *, __u32);
    __u8 (*parse_dns_payload_transport_tcp) (struct skb_cursor *, void *,  struct dns_header_tcp *, __u32); 

    __u8 (*parse_dns_payload_memsafet_payload) (struct skb_cursor *, void *, struct dns_header *); // standard dns port DPI with header always assured to be a DNS Header and dns payload 
    __u8 (*parse_dns_payload_memsafet_payload_transport_tcp) (struct skb_cursor *, void *, struct dns_header_tcp *); // standard dns port DPI with header always assured to be a DNS Header and dns payload 

    // dns header parser section fro the enitr query labels 
    __u8 (*parse_dns_payload_queries_section) (struct skb_cursor *, __u16, struct qtypes );

    // the malware can use non standard ports perform DPI with non statandard ports for DPI inside kernel matching the dns header payload section;
    __u8 (*parse_dns_payload_non_standard_port) (struct skb_cursor * , struct __sk_buff *,void *, struct dns_header *, struct udphdr *);
    __u8 (*parse_dns_payload_non_standard_port_tcp) (struct skb_cursor * , struct __sk_buff *, void *, struct dns_header_tcp *);
};

/* ***************************************** Event ring buffeers for kernel detected DNS events ***************************************** */

// non standard port DPI for enhanced c2c channels with remote c2c server for malware exfil over udp 
// an standard kernel ring buffer event for transfer with dns portocol overlay for traffic in c2c case 
struct exfil_security_egrees_clone_redirect_ring_buff_non_standard_port {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exfil_security_egrees_clone_redirect_ring_buff_non_standard_port SEC(".maps");

// vxlan encap from kernel the src port and the dest port used to detect any vxlan encap channels 
struct exfil_vxlan_exfil_event {
    __u16 transport_dest_port;
    __u16 transport_src_port;
} __attribute__((packed));

// map storing information about the vxlan kernel encap channels port for transfer, userspace instruct kernel DPI to block traffic unless scanned nexxt time via ring buff 
// userspace has always ensured that there is an l7 dns layer with malicious payload encapsulated inside the frame for vxlan packet frame.
struct exfil_vxlan_block_egress_port {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16); // userspace post DPI determines the kernel sock for the port to drop traffic 
    __type(value, __u8); // kernel flags for __u8 populated to suggest to block any traffic henceforth over this port
    __uint(max_entries, 1 << 10); // ideally matches the max (0xffff) ports over encap udp transport 
} exfil_vxlan_block_egress_port SEC(".maps");


// emits an potential ring buff kernel event with value setting an port in UDP which is potentially used to perform exfiltration and data breach 
struct exfil_security_egress_vxlan_encap_drop {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} exfil_security_egress_vxlan_encap_drop SEC(".maps");


// submits malicious DNS exfiltrated events to be exported provind processID information carrying out breaches
struct exfil_security_egress_malicious_dns_events {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} exfil_security_egress_malicious_dns_events SEC(".maps"); 


// 
struct exfil_raw_packet_mirror {
    __u16 dst_port;
    __u16 src_port;
    __u8 isUdp;
    __u8 isPacketRescanedAndMalicious;
};

// process Id and thread ID for clone redirected packet to user space for deep scan for exfiltration attempt 
struct proc_info_non_standard_port {
    __u32 processId; 
    __u32 threadId;
} __attribute__((packed));

struct exfil_security_egrees_clone_redirect_map_non_standard_port { 
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1 << 10);
    __type(key, __u16);  // src port 
    __type(value, struct proc_info_non_standard_port); // task struct for the process comm 
} exfil_security_egrees_clone_redirect_map_non_standard_port SEC(".maps"); 


/* ***************************************** Event maps for kernel ***************************************** */
// make the map struct more fine grained to prevent timing attacks from user space malware 
struct checkSum_redirect_struct_value {
    __u16 checksum; // the l3 checksum for the kernel packet before redirection 
    __u64 kernel_timets; // 
    __u32 procId; // send the process info to user space for layer over kernel syscall layer to kill this process if found malicious 
    __u32 threadId; // thread inn process task_struct comm used for sending this packet 
};

// stores inofrmation regarding checksum and the redirection of the packet from kernel 
struct exfil_security_egress_redirect_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16); // dns query id prior DPI
    __type(value, struct checkSum_redirect_struct_value);   // layer 3 checksum prior redirect using a non clone skb redirect 
    __uint(max_entries, 1 << 24);
} exfil_security_egress_redirect_map SEC(".maps");


// map used which let kernel perform DPI over different protocols with deep scan for both l4, l7 protocols to ensure data breach prvention 
// for l7 protocols like ftp, dns, smtp the kernel does packet redirection ensure map safety time attack prevention and brute force attack from user space malware 
struct exfil_security_protocols_identifier_maps {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // protocol identifier
    __type(value, __u16);   // protocol identifier populated by userspace node agent to run dpi and enhanced DPI in kernel  for both l4, l7 protocols.
    __uint(max_entries, 5); //  kernel DPI support for FTP, SMTP, (DNS done), HTTP, ICMP, IGMP 
} exfil_security_protocols_identifier_maps SEC(".maps"); 

struct exfil_security_egress_redurect_ts_verify {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64); // store the timestamp loaded from userspace when pacekt hits 
    __type(value, __u8);   // layer 3 checksum prior redirect non clone skb 
    __uint(max_entries, 1 << 15);
} exfil_security_egress_redurect_ts_verify SEC(".maps");

// kernel config map to load the config for the redirect links to egress and associated bridge if_index 
struct exfil_security_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct exfil_kernel_config);
    __uint(max_entries, 1 << 6);
} exfil_security_config_map SEC(".maps");


// useful to determine the loop back time from kernel packet redirection to user space enhanced scanning 
// the totola kernel packet redirection time - userspace post DPI time
// this is only used to find the effect of DPI scanning in userspace post redirect and then resend from user space.
struct exfil_security_egress_redirect_loop_time {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // dns query transaction id 
    __type(value, __u64); // kernel packet redirection ns 
    __uint(max_entries, 1 << 15);
} exfil_security_egress_redirect_loop_time  SEC(".maps");

// count the number of packets redirected from kernel over standard port 
struct exfil_security_egress_redirect_count_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);     // dns dest target ip over redirection  // usually the host subnet cidr gateway
    __type(value, __u32);   // count of hte packet for multiple redirection 
    __uint(max_entries, 1);
} exfil_security_egress_redirect_count_map SEC(".maps");

// count the number of packets clone redirected from kernel over potential non_standard Port Exfiltration 
struct exfil_security_egress_clone_redirect_count_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);     // dns dest target ip over redirection  // usually the host subnet cidr gateway
    __type(value, __u32);   // count of hte packet for multiple redirection 
    __uint(max_entries, 1);
} exfil_security_egress_clone_redirect_count_map SEC(".maps");

// count the number of packets clone redirected from kernel over potential non_standard Port Exfiltration, post user space deep scan and dropped by kernel over egress 
struct exfil_security_egress_clone_redirect_drop_kernel_count_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);     // dns dest target ip over redirection  // usually the host subnet cidr gateway
    __type(value, __u32);   // count of hte packet for multiple redirection 
    __uint(max_entries, 1);
} exfil_security_egress_clone_redirect_drop_kernel_count_map SEC(".maps");

// count the number of packets over reidrect to drop linux ns
struct exfil_security_egress_redirect_drop_count_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);     // dns dest target ip over redirection  // usually the host subnet cidr gateway
    __type(value, __u32);   // count of hte packet for multiple redirection 
    __uint(max_entries, 1);
} exfil_security_egress_redirect_drop_count_map SEC(".maps");

struct exfil_security_egress_vxlan_dns_transport {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u8);  // the vxlan port dest gateway id for packet redirection from kernel 
    __type(value, __u32);   // count of the tunnel dns packet clone skb redirect from skb for DPI in userspace over vxlan
    __uint(max_entries, 1);
} exfil_security_egress_vxlan_dns_transport SEC(".maps");


/* ***************************************** Event maps for Egress Traffiic Rate Limiting ***************************************** */
struct dns_volume_stats {
    __u64 last_timestamp;
    __u32 packet_size;
};

// exfil rate limiter 


// follows leaky bucket algortihm with ebpf lru map inside kernel operating anf moniting dns traffic over single window utilizing volume of traffic over a fixed 1 sec window
// the packet does not matter (dns + tcpv4 / tcpv6) or (dns + udpv4 + udpv6)
#if DNS_RATE_LIMIT_VOLUME 
    struct exfil_security_egress_volume_rate_limit_map {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u16);
        __type(value, struct dns_volume_stats);
        __uint(max_entries, 1);
    } exfil_security_egress_volume_rate_limit_map SEC(".maps");
#endif

// follows token bucket algortihm with ebpf lru map inside kernel operating anf moniting dns traffic over single window utilizing dns rps over reaching the egress kernel TC 
#if DNS_RATE_LIMIT_TOCKEN_BUCKET
    struct exfil_security_egress_tb_rate_limit_map {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u16);
        __type(value, struct dns_volume_stats);
        __uint(max_entries, 1);
    } exfil_security_egress_tb_rate_limit_map SEC(".maps");
#endif 


// dynamic netpool l3 ipv4 filtering for any malicious traffic found to upstream servers 
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    struct exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 1 << 10);
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


// Parse the RAW SKB for query classes 
#define EXFIL_SECURITY_FILTER_DNS_QUERY_CLASS(dns_query_class)\ 
        switch ((dns_query_class)){                 \
                case 0x0001:                        \
                case 0x0002:                        \
                case 0x0005:                        \
                case 0x0006:                        \
                case 0x001C:                        \
                case 0x0041:                        \
                    return BENIGN;                  \
                case 0x000F:                        \
                case 0x0021:                        \
                case 0x0023:                        \
                case 0x0029:                        \
                case 0x0010:                        \
                    return SUSPICIOUS;              \
                case 0x00FF:                        \
                case 0x000A:                        \
                    return MALICIOUS;               \
                default:                            \
                    return SUSPICIOUS;              \
            }                                       

// custom range order filtering for the DNS domains over the labels queries ssections 
#define SUBDOMAIN_RANGE_FILTER(subdomain_label_count,subdomain_label_count_config_min_key,subdomain_label_count_config_max_key)                             \
    if (!DEBUG)                                                                                                                                             \
        bpf_printk("subdomain count %d ", subdomain_label_count);                                                                                           \
    __u32 * subdomain_label_count_config_min_map = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &subdomain_label_count_config_min_key);          \
    if (!subdomain_label_count_config_min_map) *subdomain_label_count_config_min_map = DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_EXCLUDING_TLD;                \
    __u32 * subdomain_label_count_config_max_map = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &subdomain_label_count_config_max_key);          \
    if (!subdomain_label_count_config_max_map) *subdmoain_label_count_config_max_map = DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_EXCLUDING_TLD;                \
    if (subdmoain_label_count >= subdmoain_label_count_config_min_map && subdmoain_label_count <= subdmoain_label_count_config_max_map) return SUSPICIOUS;  \
    if (subdmoain_label_count > subdmoain_label_count_config_max_map) return MALICIOUS;                                                                     \


// this will used as a l3 netpool to filter any protocol overlay with this blocklisted ipaddress in its l3 ipv4 header 
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS 
    #define EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV4(ip)                                   \
        do {                                                                            \
            if (L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS) {  \
                if (__l3_ipv4_netpool_egress_filter_for_dns_c2_server(ip)) {            \
                    if (!DEBUG) {                                                       \
                        bpf_printk("dropping traffic for malicious c2 ipv4 remote c2"); \
                    }                                                                   \
                    return TC_DROP;                                                     \
                }                                                                       \
            }                                                                           \
        } while(0)                                                                      
#endif

// this will used as a l3 netpool to filter any protocol overlay with this blocklisted ipaddress in its l3 ipv6 header 
#if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS      
    #define EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV6(ip)                                   \ 
    do {                                                                                \
            if (L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS) {  \
                if (__l3_ipv6_netpool_egress_filter_for_dns_c2_server(ip)) {            \
                    if (DEBUG) {                                                        \
                        bpf_printk("dropping traffic for malicious c2 ipv6 remote c2"); \
                    }                                                                   \
                    return TC_DROP;                                                     \
                }                                                                       \
            }                                                                           \
    } while(0)        
#endif 

static 
__always_inline void cursor_init(struct skb_cursor *cursor, struct __sk_buff *skb){
    cursor->data = (void *)(ll)(skb->data);
    cursor->data_end = (void *)(ll)(skb->data_end);
}

static 
__always_inline __u8 parse_eth(struct skb_cursor *skb) {
    struct ethhdr *eth = skb->data;
    if ((void *) (eth + 1) > skb->data_end) return 0;  // should strictly be in skb kernel boundary
    return 1;
}

static 
__always_inline __u8 parse_ipv4(struct skb_cursor *skb) {
    struct iphdr *ip = skb->data + sizeof(struct ethhdr);

    if ((void *) (ip + 1) > skb->data_end ) return 0; // should strictly be in skb kernel boundary
  
    return 1;
}

static 
__always_inline __u8 parse_ipv6(struct skb_cursor *skb) {
    struct ipv6hdr *ipv6 = skb->data + sizeof(struct ethhdr);
    if ((void *)(ipv6 + 1) > skb->data_end) return 0;
    return 1;
}

static 
__always_inline __u8 process_udp_payload_mem_verification(struct udphdr *udp, struct skb_cursor *skb, bool isIPv4) {
    __u16 udp_len = bpf_ntohs(udp->len);
    __u16 udp_len_payload = udp_len - sizeof(struct udphdr); // Ensure payload size is valid

    // Pointer to the start of the UDP payload
    void *udp_data = skb->data + sizeof(struct ethhdr) + (isIPv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) + sizeof(struct udphdr);

    // Check if the UDP payload fits within the packet
    if ((void *)udp_data + udp_len_payload > skb->data_end) {
        return 0;  // Return error for the kernel memory limit exceed for memory safety 
    }

    // Check if the UDP payload fits within the packet
    if ((void *)udp_data + udp_len_payload > skb->data_end) {
        return 0;  // Return error for the kernel memory limit exceed for memory safety 
    }

    return 1;
}


static 
__always_inline __u8 parse_udp(struct  skb_cursor *skb, bool isIpv4) {

    struct udphdr *udp = skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    if ((void *)(udp + 1) > skb->data_end) return 0;

    if (process_udp_payload_mem_verification(udp, skb, isIpv4 ? true : false) == 0) 
        return 0;
    
    return 1;
}

static 
__always_inline __u8 parse_tcp(struct  skb_cursor *skb, bool isIpv4) {
    struct tcphdr *tcp = skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    if ((void *)(tcp+ 1) > skb->data_end) return 0;

    return 1;
}

static 
__always_inline __u8 parse_dns_header_size(struct skb_cursor *skb, bool isIpv4, bool isTCP) {
    // verify the dns header payload from root of the skbuff 

    if (skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) +  (isTCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) + sizeof(struct dns_header) > skb->data_end) {
        // this is definitely not a layer 7 dns header allow this to be classified for a valid action 
        return 0;
    }

    return 1;
}


static 
__always_inline __u8 parse_dns_payload_udp(struct skb_cursor *skb, void * dns_payload, 
            __u32 udp_payload_len, __u32 udp_payload_exclude_header, struct dns_header * dns_header, __u32 skb_len) {
        
        // the kernel verifier enforce and need to be strict and assume the buffer is validated before itself 

        if (udp_payload_len > skb_len || udp_payload_exclude_header > skb_len) return 0;


        return 1;
}

static 
__always_inline __u8 parse_dns_payload_tcp(struct skb_cursor *skb, void *dns_payload, struct dns_header_tcp * dns_header, __u32 skb_len) {
    if ((void *) dns_payload + sizeof(*dns_header) > skb->data_end) return 0;
    return 1;
}

static
  __always_inline __u8 parse_dns_qeury_type_section(struct skb_cursor *skb, __u16 dns_query_class, struct qtypes qt) {

        EXFIL_SECURITY_FILTER_DNS_QUERY_CLASS(dns_query_class)
        return SUSPICIOUS;
  }

static 
__always_inline struct result_parse_dns_labels check_for_c2c_health_process(__u16 dns_query_class, struct qtypes qt, 
                __u8 total_domain_length, __u8 total_domain_length_exclude_tld) {
        // check for the c2c record types used by remote malware processes 
        struct result_parse_dns_labels resuult = {
            .deep_scan_mirror = false, 
            .drop = false, 
            .isBenign = false,
            .isC2c = false,
        };
        if (dns_query_class == qt.MX || dns_query_class == qt.TXT || dns_query_class == qt.CNAME){
            if (dns_query_class == qt.TXT) {
                if (total_domain_length >= MAX_DNS_PAYLOAD_TXT_LENGTH) {
                    resuult.drop = true;
                }else {
                    resuult.deep_scan_mirror = true;
                }
            }else if (dns_query_class == qt.MX) {
                if (total_domain_length >= MAX_DNS_PAYLOAD_MX_LENGTH) {
                    resuult.drop = true;
                }else {
                    resuult.deep_scan_mirror = true;
                }
            }else {
                resuult.deep_scan_mirror = true;
            }
            resuult.isC2c = true; 
        }
        return resuult;
}

static 
__always_inline __u8 parse_dns_payload_memsafet_payload(struct skb_cursor *skb, void *dns_payload, 
                struct dns_header *dns_header){
    // dns header already validated and payload and header memory safetyy already cosnidered 


    struct dns_flags flags = get_dns_flags(dns_header);
    #if DEBUG
        bpf_printk("the auth question count are %u %u", bpf_ntohs(dns_header->qd_count), bpf_ntohs(dns_header->ans_count));
        bpf_printk("the addon question count are %u %u", bpf_ntohs(dns_header->add_count), bpf_ntohs(dns_header->auth_count));
        bpf_printk("the query opcode %d",  flags.opcode);
    #endif

    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    // the size of char containing the dns payload char size 
    __u8 *dns_payload_buffer = (__u8 *) dns_payload;
    /*
        Usually the c2 implant and tunelling tools sends 1 request query per DNS packet  to the remote DNS server 
        DNS exfiltration attacks, malware can hide and transmit data not only in the questions section of DNS queries but also in other sections, making it more flexible and stealthy
    */

   if (qd_count == 1) {
     if (ans_count == 0) {
        // a questions record and its an benign packet but need DPI and kernel can do DPI for the entire packet frame 
        qd_count = 1; // let the ebpf verifier proceed during JIT and memory check 

        if (auth_count >= 1) {
            return SUSPICIOUS;
        }

        if (add_count > 1) return SUSPICIOUS;
        // each kernel config limit value internally stores (priority | value) --> (0x100 + priority) | limit

        // subdomain label count inference based on the state 
        __u32 label_key_subdomain_per_label_min = 2; __u32 label_key_subdomain_per_label_max = 3;
        __u32 label_key_subdomain_length_exclude_tld_min = 6; __u32 label_key_subdomain_length_exclude_tld_max = 7;

        // label count inference based on the configured state 
        __u32 label_key_label_count_min = 4; __u32 label_key_label_count_max = 5;
        __u32 label_key_total_domain_length_min = 0; __u32 label_key_total_domain_length_max = 1;
        
        // values 
        __u32 * MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_per_label_min);
        __u32 * MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_per_label_max);
        __u32 * MIN_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_length_exclude_tld_min);
        __u32 * MAX_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_length_exclude_tld_max);

        // label count for domain 
        __u32 * MIN_LABEL_COUNT_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_label_count_min);
        __u32 * MAX_LABEL_COUNT_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_label_count_max);
        __u32 * MIN_TOTAL_DOMAIN_LENGTH_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_total_domain_length_min);
        __u32 * MAX_TOTAL_DOMAIN_LENGTH_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_total_domain_length_max);

        __u8 total_domain_length = 0;
        __u8 total_domain_length_exclude_tld = 0;
        // Iter through the Questions Count
        for (__u8 i=0; i < qd_count; i++){
            __u8 offset = 0;
            __u8 label_count = 0; __u8 mx_label_ln = 0;

            __u8 root_domain  = 0;

            // parse the QNAME
            // iter over the char labels in QNAME
            for (int j=0; j < MAX_DNS_NAME_LENGTH; j++){
                if ((void *) (dns_payload_buffer + offset + 1 ) > skb->data_end) return SUSPICIOUS;

                __u8 label_len = *(__u8 *)  (dns_payload_buffer + offset);
                mx_label_ln = max(mx_label_ln, label_len);

                #if DEBUG
                    char buff[MAX_DNS_LABEL_LENGTH];
                #endif

                #if !SUBDOMAIN_RANGE_LABEL_CHAR_SCAN
                    __u8 iter_label_chars_ln = label_len;
                    if (iter_label_chars_ln >= MAX_DNS_LABEL_LENGTH)
                        iter_label_chars_ln = MAX_DNS_LABEL_LENGTH;

                    #if DEBUG
                        for (int i = 0; i < MAX_DNS_LABEL_LENGTH; i++)
                            buff[i] = '\0';
                    #endif
                    
                    __u8 *dns_payload_start = (__u8 *)(void *)(dns_payload_buffer + offset + sizeof(__u8));
                    if ((void *)dns_payload_start + 1 > skb->data_end) {
                        goto parsed_label_queryHandler;
                    }
                
                    __u8 lower_ct = 0; __u8 upper_ct = 0;
                    __u8 digit_ct = 0; __u8 spec_char = 0;

                    __u8 curr_parsed_jumps = 0;
                    __u8 buffer_lab_ind = 0;
                
                next_char_parse:
                    if ((void *)(dns_payload_start + 1) > skb->data_end)
                        goto parsed_label_queryHandler;
                
                    char dns_payload_start_chr = (char)(*dns_payload_start);
                    #if DEBUG
                        buff[buffer_lab_ind] = dns_payload_start_chr;
                    #endif

                    dns_payload_start = dns_payload_start + sizeof(__u8);
                
                    if (isLower(dns_payload_start_chr))
                        lower_ct++;
                    if (isUpper(dns_payload_start_chr))
                        upper_ct++;
                    if (isDigit(dns_payload_start_chr))
                        digit_ct++;
                    else spec_char++;

                    curr_parsed_jumps++;
                    buffer_lab_ind++;

                    if (buffer_lab_ind >= MAX_DNS_LABEL_LENGTH)
                        goto parsed_label_queryHandler;
                    
                    if ((void *) dns_payload_start > skb->data_end)
                        goto parsed_label_queryHandler;
                    
                    goto next_char_parse;
                    
                    if (spec_char > (int) spec_char / 2) return SUSPICIOUS;
                parsed_label_queryHandler:
                #endif
                
                if (label_len == 0x00) break;
                label_count++;

                if (root_domain > 2)
                    total_domain_length_exclude_tld += label_len;
                else 
                    root_domain++;

                total_domain_length += label_len;
                offset += label_len + 1; 
                if ((void *) (dns_payload_buffer + offset) > skb->data_end) return SUSPICIOUS;
            }

            if (label_count > MAX_DNS_LABEL_COUNT) label_count = MAX_DNS_LABEL_COUNT;
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;

            // parse the QTYPE
            __u16 query_type = *(__u16 *) (dns_payload_buffer + offset); 
            
            offset += sizeof(__u16);
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;

             // parse the QCLASS
             __u16 query_class = *(__u16 *) (dns_payload_buffer + offset);
            offset += sizeof(__u16); // offset += sizeof(__u8) + 1;

            __u8 subdmoain_label_count = root_domain == 2 ? 0 : label_count - 2;
            

            struct result_parse_dns_labels c2c_check = check_for_c2c_health_process(query_class, qtypes, total_domain_length, total_domain_length_exclude_tld);

            if (label_count <= 2 && !c2c_check.isC2c) return BENIGN;
            

            __u8 dns_query_labels =  parse_dns_qeury_type_section(skb, query_class, qtypes);
                
            if (dns_query_labels == MALICIOUS) return MALICIOUS;

            __u32 prio_features_suspicious = 0x00; // match the features which user space enforce in kernel 
            __u8 prio_violate_count[MAX_DNS_PRIO_KEYS] = {0};

            // subdomain length per label (min | max)
            if (MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP != NULL && MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP != NULL) {
                    if (mx_label_ln >= (*MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP & 0xff) && mx_label_ln <= (*MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP & 0xff)) {
                        __u8 feature_prio = (*MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP) >> 8; // consider any key since min and max range has same prio in kernel eBPF map 
                        if (feature_prio > MAX_DNS_PRIO_KEYS) 
                            feature_prio = MAX_DNS_PRIO_KEYS;
                        prio_violate_count[feature_prio]++;
                        prio_features_suspicious += 1;
            }
            }else if (mx_label_ln >= (DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_PER_LABEL & 0xff) && 
                            mx_label_ln <= (DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_PER_LABEL & 0xff)){
                        __u8 feature_prio = (DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_PER_LABEL) >> 8;
                        if (feature_prio > MAX_DNS_PRIO_KEYS) 
                            feature_prio = MAX_DNS_PRIO_KEYS;
                        prio_violate_count[feature_prio]++;
                        prio_features_suspicious++;
            }

            // label count (min | max)
            if (MIN_LABEL_COUNT_KERNEL_MAP != NULL && MAX_LABEL_COUNT_KERNEL_MAP != NULL){
                if (label_count >= (*MIN_LABEL_COUNT_KERNEL_MAP & 0xff) && label_count <= (*MAX_LABEL_COUNT_KERNEL_MAP & 0xff)) {
                        __u8 feature_prio = (*MIN_LABEL_COUNT_KERNEL_MAP) >> 8;
                        if (feature_prio > MAX_DNS_PRIO_KEYS) 
                            feature_prio = MAX_DNS_PRIO_KEYS;
                        prio_violate_count[feature_prio]++;
                        prio_features_suspicious++;
                }
            }else if (label_count >= (DNS_RECORD_LIMITS.MIN_LABEL_COUNT & 0xff) && label_count <= (DNS_RECORD_LIMITS.MAX_LABEL_COUNT & 0xff)){
                    __u8 feature_prio = (DNS_RECORD_LIMITS.MAX_LABEL_COUNT) >> 8;
                    if (feature_prio > MAX_DNS_PRIO_KEYS) 
                        feature_prio = MAX_DNS_PRIO_KEYS;
                    prio_violate_count[feature_prio]++;
                    prio_features_suspicious++;
            }

            // total domain length (min | max) 
            if (MIN_TOTAL_DOMAIN_LENGTH_KERNEL_MAP != NULL && MAX_TOTAL_DOMAIN_LENGTH_KERNEL_MAP != NULL) {
                if (total_domain_length >= (*MIN_TOTAL_DOMAIN_LENGTH_KERNEL_MAP & 0xff) && 
                total_domain_length <= (*MAX_TOTAL_DOMAIN_LENGTH_KERNEL_MAP & 0xff)) {
                    __u8 feature_prio = (*MIN_TOTAL_DOMAIN_LENGTH_KERNEL_MAP) >> 8;
                    if (feature_prio > MAX_DNS_PRIO_KEYS)
                        feature_prio = MAX_DNS_PRIO_KEYS;
                    prio_violate_count[feature_prio]++;
                    prio_features_suspicious++;
                }
            } else if (total_domain_length >= (DNS_RECORD_LIMITS.MIN_DOMAIN_LENGTH & 0xff) && 
                total_domain_length <= (DNS_RECORD_LIMITS.MAX_DOMAIN_LENGTH & 0xff)) {
                    __u8 feature_prio = (DNS_RECORD_LIMITS.MAX_DOMAIN_LENGTH) >> 8;
                    if (feature_prio > MAX_DNS_PRIO_KEYS)
                        feature_prio = MAX_DNS_PRIO_KEYS;
                    prio_violate_count[feature_prio]++;
                    prio_features_suspicious++;
            }

            // subdomain length excludes tld (min | max)
            if (MIN_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP != NULL && MAX_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP != NULL) {
                if (total_domain_length_exclude_tld >= (*MIN_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP & 0xff) && 
                    total_domain_length_exclude_tld <= (*MAX_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP & 0xff)) {
                        __u8 feature_prio = (*MIN_SUBDOMAIN_LENGTH_EXCLUDE_TLD_MIN_KERNEL_MAP) >> 8;
                        if (feature_prio > MAX_DNS_PRIO_KEYS)
                            feature_prio = MAX_DNS_PRIO_KEYS;
                        prio_violate_count[feature_prio]++;
                        prio_features_suspicious++;
                }
            } else if (total_domain_length_exclude_tld >= (DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_EXCLUDING_TLD & 0xff) && 
                       total_domain_length_exclude_tld <= (DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_EXCLUDING_TLD & 0xff)) {
                        __u8 feature_prio = (DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_EXCLUDING_TLD) >> 8;
                        if (feature_prio > MAX_DNS_PRIO_KEYS)
                            feature_prio = MAX_DNS_PRIO_KEYS;
                        prio_violate_count[feature_prio]++;
                        prio_features_suspicious++;
            }


            if (prio_features_suspicious > 0) {
                bool isHighPrioMarkFeatureViolated = false;
                for (int i =0; i < MAX_DNS_PRIO_KEYS; i++) {
                    if ( i > 0) {
                        isHighPrioMarkFeatureViolated = prio_violate_count[i] > 0 ? true : false;
                    }else if (prio_violate_count[i] > 0 && isHighPrioMarkFeatureViolated) 
                        return SUSPICIOUS;
                }
                return SUSPICIOUS;
            }

            if (c2c_check.isC2c) {
                if (c2c_check.deep_scan_mirror) return SUSPICIOUS;
                if (c2c_check.drop) return MALICIOUS;
                if (!c2c_check.deep_scan_mirror && !c2c_check.drop) return BENIGN;
            }

            return BENIGN;
        }
     }else return SUSPICIOUS;
   }

   return SUSPICIOUS;
}   


static 
__always_inline __u8 parse_dns_payload_memsafet_payload_transport_tcp(struct skb_cursor *skb, void *dns_payload, 
            struct dns_header_tcp *dns_header) {
    // dns header already validated and payload and header memory safetyy already cosnidered 

    // debug the size and content of questions, answer auth and add count in dns header 

    struct dns_flags flags = get_dns_flags_tcp(dns_header);
    #if DEBUG
        bpf_printk("the auth question count are %u %u", bpf_ntohs(dns_header->qd_count), bpf_ntohs(dns_header->ans_count));
        bpf_printk("the addon question count are %u %u", bpf_ntohs(dns_header->add_count), bpf_ntohs(dns_header->auth_count));
        bpf_printk("the query opcode %d",  flags.opcode);
        }
    #endif

    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    // the size of char containing the dns payload char size 
    __u8 *dns_payload_buffer = (__u8 *) dns_payload;
    /*
        Usually a dns resolver sends 1 request query for a single request to the remote DNS server 
        The clsact qdisc is only meant for egress traffic and tc control flow system after fa_codel or any non-leaf classfull qdisc
                 default tc action from kernel
        Direct action appled over the egress traffic 
        DNS exfiltration attacks, malware can hide and transmit data not only in the questions section of DNS queries but also in other sections,
                 making it more flexible and stealthy
    */

   if (qd_count == 1) {
     if (ans_count == 0) {
        // a questions record and its an benign packet but need DPI and kernel can do DPI for the entire packet frame 
        qd_count = 1; // let the ebpf verifier proceed during JIT and memory check 

        if (auth_count >= 1) {
            return SUSPICIOUS;
        }

        if (add_count > 1) return SUSPICIOUS;

        // for EDNS servers the request can sedn auth OPT records allow to pass through the kernel 
        __u32 label_key_subdomain_per_label_min = 2;  __u32 label_key_subdomain_per_label_max = 3;
        __u32 label_key_label_count_min = 4; __u32 label_key_label_count_max = 5;
        
        __u32 * MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_per_label_min);
        __u32 * MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_subdomain_per_label_max);
        __u32 * MIN_LABEL_COUNT_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_label_count_min);
        __u32 * MAX_LABEL_COUNT_KERNEL_MAP = bpf_map_lookup_elem(&exfil_security_egress_dns_limites, &label_key_label_count_max);

        __u8 total_domain_length_exclude_tld = 0;
        for (__u8 i=0; i < qd_count; i++){
            __u16 offset = 0;
            __u8 label_count = 0; __u8 mx_label_ln = 0;

            __u8 root_domain  = 0;

            // parse the QNAME
            for (int j=0; j < MAX_DNS_NAME_LENGTH; j++){
                if ((void *) (dns_payload_buffer + offset + 1 ) > skb->data_end) return SUSPICIOUS;

                __u8 label_len = *(__u8 *)  (dns_payload_buffer + offset);
                mx_label_ln = max(mx_label_ln, label_len); 
                if (label_len == 0x00) break;
                label_count++;
 
                if (root_domain > 2)
                    total_domain_length_exclude_tld += label_len;
                else 
                    root_domain++;

                offset += label_len + 1; 
                if ((void *) (dns_payload_buffer + offset) > skb->data_end) return SUSPICIOUS;
            }
            
            __u16 query_type; __u16 query_class;
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;
            // parse the QTYPE
            query_type = *(__u16 *) (dns_payload_buffer + offset); 
            
            offset += sizeof(__u16);
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;

            // parse the QCLASS
            query_class = *(__u16 *) (dns_payload_buffer + offset);
            offset += sizeof(__u16); // offset += sizeof(__u8) + 1;

            __u8 subdmoain_label_count = root_domain == 2 ? 0 : label_count - 2;

            if (label_count <= 2) return BENIGN;
            

            if (MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP != NULL && MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP != NULL) {
                    if (mx_label_ln >= *MIN_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP && mx_label_ln <= *MAX_SUBDOMAIN_LENGTH_PER_LABEL_KERNEL_MAP) return SUSPICIOUS;
            }else if (mx_label_ln >= DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_PER_LABEL && mx_label_ln <= DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_PER_LABEL){
                    return SUSPICIOUS;
            }

            if (MIN_LABEL_COUNT_KERNEL_MAP != NULL && MAX_LABEL_COUNT_KERNEL_MAP != NULL){
                if (label_count >= *MIN_LABEL_COUNT_KERNEL_MAP && label_count <= *MAX_LABEL_COUNT_KERNEL_MAP) return SUSPICIOUS;
            }else if (label_count > DNS_RECORD_LIMITS.MIN_LABEL_COUNT && label_count <= DNS_RECORD_LIMITS.MAX_LABEL_COUNT){
                // bpf_printk("invoked on  label_count %d", label_count);
                return SUSPICIOUS;
            }
            
            if (total_domain_length_exclude_tld >= DNS_RECORD_LIMITS.MIN_DOMAIN_LENGTH && total_domain_length_exclude_tld <= DNS_RECORD_LIMITS.MAX_DOMAIN_LENGTH){
                // bpf_printk("invoked on  total domain length %d", total_domain_length_exclude_tld);
                return SUSPICIOUS;
            }

            return parse_dns_qeury_type_section(skb, query_class, qtypes);
        }
     }else return SUSPICIOUS;
   }else {
        /// the question is malicious since the malicious client is sending multiple questions a C2C where malware is asking next commands 
        return SUSPICIOUS;
   }

   return BENIGN;
}   


/*
    Emit the kernel event to user space to bind and read traffic over the port 
    Userspace should clean the dptr kernel only emits dptr dynamic events for user space to sniff the traffic on these ports to read udp traffic post parsing and processing the vxlan header 
    If a vxlan transfer with malicious dns is found the user space update map to ensure kernel drop the  packet through UDP over vxlan net_device / link in kernel 
*/
static
__always_inline void __emit_kernel_encap_event_vxlan_encap(struct udphdr *udp, __u32 egress_ifindex) {
    struct bpf_dynptr dptr;
    if (bpf_ringbuf_reserve_dynptr(&exfil_security_egress_vxlan_encap_drop, sizeof(struct exfil_vxlan_exfil_event), 0, &dptr) < 0){
        #if DEBUG
            bpf_printk("Error allocating memory for dynamic ptr size in ring buffer");
        #endif
        bpf_ringbuf_discard_dynptr(&dptr, 0);
        return;
    }
    #if DEBUG
        bpf_printk("emit an vxlan kernel event for udp %u %u", bpf_ntohs(udp->dest), bpf_ntohs(udp->source));
    #endif
    struct exfil_vxlan_exfil_event vxlan_event = (struct exfil_vxlan_exfil_event) {
        .transport_dest_port = bpf_ntohs(udp->dest),
        .transport_src_port = bpf_ntohs(udp->source)
    };
    bpf_dynptr_write(&dptr, 0, &vxlan_event, sizeof(struct exfil_vxlan_exfil_event), 0);
    bpf_ringbuf_submit_dynptr(&dptr, 0);
    bpf_printk("Emit the vxlan encap tracing event to user space");
}


/*
    The kernel does a packet tunneling usually over the epheral udp port (4379) and not a standard dns tunnel for packet forward
        kernel never allows the packet to pass over standard dns udp l4 to be encapsulated as a vxlan inside the main packet. 
*/
static 
__always_inline __u8 __parse_encap_vxlan_tunnel_header(struct skb_cursor *skb, void * transport_payload) {
    /*
        vxland is tunnel traffic for all upto layer 7 inside layer 4 with a valid vni header at start 
    */

    struct vxlanhdr *vxlan = (struct vxlanhdr *)transport_payload;
    if ((void *)vxlan + sizeof(struct vxlanhdr) > skb->data_end)  return BENIGN;

    if (__parse_vxlan_flag__hdr(transport_payload, vxlan, skb->data_end) == 0) return BENIGN;

    __u32 vlan_id = __parse_vxlan_vni_hdr(transport_payload, vxlan, skb->data_end);


    // do an raw head parsing from the skb->data until the detection for any l7 traffic
    void *payload = (void *)vxlan + sizeof(struct vxlanhdr);
    if ((void *) payload + sizeof(struct ethhdr) > skb->data_end) return BENIGN;

    struct ethhdr *eth = (struct ethhdr *)payload;
    if ((void*)(eth + 1) > skb->data_end)
        return BENIGN;
    
    // debug potential vxlan encap or tunnel vni parsed 
    #if DEBUG
        bpf_printk("Suspicious vxlan tunnel detected started trecursive internal parsing for the skb header with vni %d", vlan_id);
        bpf_printk("the next header for eth packet in vxlan is %x %x", eth->h_proto, bpf_htons(ETH_P_IP));
    #endif

    /*
        Do further nested deep scan to check really the packet has dns with an encap frame in it in skb 
    */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > skb->data_end) return BENIGN;
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if ((void *)(udp + 1) > skb->data_end) return BENIGN;
            struct dns_header *dns_header = (struct dns_header *)(udp + 1);
            if ((void *)(dns_header + 1) > skb->data_end) return BENIGN;
            return SUSPICIOUS;
        }else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if ((void *)(tcp + 1) > skb->data_end) return BENIGN;
            struct dns_header *dns_header = (struct dns_header *)(tcp + 1);
            if ((void *)(dns_header + 1) > skb->data_end) return BENIGN;
            return SUSPICIOUS;
        }
    }else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ipv6 + 1) > skb->data_end) return BENIGN;
        if (ipv6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ipv6 + 1);
            if ((void *)(udp + 1) > skb->data_end) return BENIGN;
            struct dns_header *dns_header = (struct dns_header *)(udp + 1);
            if ((void *)(dns_header + 1) > skb->data_end) return BENIGN;
            return SUSPICIOUS;
        }else if (ipv6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ipv6 + 1);
            if ((void *)(tcp + 1) > skb->data_end) return BENIGN;
            struct dns_header *dns_header = (struct dns_header *)(tcp + 1);
            if ((void *)(dns_header + 1) > skb->data_end) return BENIGN;
            return SUSPICIOUS;
        }
        return BENIGN;
    }
    return BENIGN;
}

static 
__always_inline __u8 parse_dns_payload_non_standard_port(struct skb_cursor * skb, struct __sk_buff *raw_skb,void *dns_payload, 
                struct dns_header *dns_header, struct udphdr *udp) {
    // check whether a non standard port is used for dns query and dns payload 
    
    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);   
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    //bpf_printk("NON STANDARD Port used over similar dns standard header further DPI %u %u", qd_count, ans_count);
    if (qd_count > (1 << 8) - 1 || ans_count > (1 << 8) - 1 || auth_count > (1 << 8) - 1 || add_count >  (1 << 8) - 1) {
        // the dns payload is non standard port and the protcol encapsulated used is not dns 
        return 1;
    }

    if (ans_count == 0) {
        // a potential question section embed inside deep for the __sk_buff processing;
        // if (parse_dns_payload_memsafet_payload() == SUSPICIOUS) {
        
        // verify header opcodes and return types 
        __u16 raw_dns_flags = dns_header->flags;
        #if DEBUG
                bpf_printk("the raw kernel parsed flags are %u", raw_dns_flags);
        #endif

        struct dns_flags dns_header_flags = get_dns_flags(dns_header);
        
        // 1, verify the opcodes, and rcode raw parse from the header 
        if (dns_header_flags.opcode > valid_opcodes[1]) return 1;
        if (dns_header_flags.rcode >= 24) return 1;

        return 0;
    }else if (ans_count > 0 && ans_count <= (1 << 8) - 1)
        return 1; // the tc egress is a egress control traffic filter hte node does not belong to a dns server to have answer at egress 
    // let the kernel do no standard chcek inside kernel sicne normal tunnelling over this port is never done by standard udp traffic 
    if (DEBUG)
        bpf_printk("Non standard transport DPI found for exfil remote c2c server");
    // a malicious encap is used to mask the dns traffPic 
    return 0;
}


static 
__always_inline __u8 parse_dns_payload_non_standard_port_tcp(struct skb_cursor *skb, struct __sk_buff *raw_skb, void * dns_payload, 
                struct dns_header_tcp *dns_header) {
                    
    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);   
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    //bpf_printk("NON STANDARD Port used over similar dns standard header further DPI %u %u", qd_count, ans_count);
    if (qd_count >= (1 << 8) - 1 || ans_count >= (1 << 8) - 1 || auth_count >= (1 << 8) - 1 || add_count >= (1 << 8) - 1) {
        // the dns payload is non standard port and the protcol encapsulated used is not dns 
        return 1;
    }

    if (ans_count == 0) {
        // a potential question section embed inside deep for the __sk_buff processing;
        
        // verify header opcodes and return types 
        __u16 raw_dns_flags = dns_header->flags;
        #if DEBUG
                bpf_printk("the raw kernel parsed flags are %u", raw_dns_flags);
        #endif

        struct dns_flags dns_header_flags = get_dns_flags_tcp (dns_header); // padding length in raw skb added for parsing 
        
        // verify the opcodes, and rcode raw parse from the skb  
        if (dns_header_flags.opcode > valid_opcodes[1]) return 1;
        if (dns_header_flags.rcode >= 24) return 1;

        return 0;
    }else if (ans_count > 0 && ans_count <= (1 << 8) - 1)
        return 1; 

    // let the kernel do no standard chcek inside kernel sicne normal tunnelling over this port is never done by standard udp traffic 
    #if DEBUG
        bpf_printk("Non standard transport DPI found for exfil remote c2c server");
    #endif
    // a malicious encap is used to mask the dns traffPic 
    return 0;
}

static 
__always_inline void __handle_kernel_map_clone_redirected_count(bool isRedirectedDropped) {
    #if DEBUG
        bpf_printk("Updating the kernel maps for clone redirection from kernel ");
    #endif 
    __u16 redirection_count_key = 0; // keep constant from kernel to measure the redirection count 
    if (isRedirectedDropped) {
        __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_clone_redirect_drop_kernel_count_map, &redirection_count_key);
        if (ct_val) 
            __sync_fetch_and_add(ct_val, 1); // increase clone redirection buffer count
        else {
            const __u32 init_map_redirect_count = 1;
            bpf_map_update_elem(&exfil_security_egress_clone_redirect_drop_kernel_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
        }
    }else {
        __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_clone_redirect_count_map, &redirection_count_key);
        if (ct_val) 
            __sync_fetch_and_add(ct_val, 1); // increase clone redirection buffer count
        else {
            const __u32 init_map_redirect_count = 1;
            bpf_map_update_elem(&exfil_security_egress_clone_redirect_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
        }
    }
}


static 
__always_inline __u8 __clone_redirect_packet(struct __sk_buff *skb, __u32 br_index, 
        __be32 dest_addr_route, bool isMarkRandSkb) {

    __be32 current_dest_addr; 
    
    if (isMarkRandSkb) {
        __u32 out = skb->ifindex;
        struct exfil_kernel_config * config =  bpf_map_lookup_elem(&exfil_security_config_map, &out);

        if (!config) {
            skb->mark = redirect_skb_mark;
        }else {
            skb->mark = config->KernelTCSKBMark;
        }
    }
    if (bpf_skb_load_bytes(skb, IP_DST_OFF, &current_dest_addr, 4) < 0) {
        bpf_printk("Error Loading the IP Destination Address for malicious redirect"); 
        return -1;
    } 
    // change the ipv4 layer 3 for redirect of the entire tcp packet over the other ns bridge 
    __u32 csum_diff_drop = bpf_csum_diff(&current_dest_addr, 4, &dest_addr_route, 4, 0);

    if (IP_DST_OFF > skb->len) {
        return -1;  // Check if offset is within bounds
    }

    if (bpf_l3_csum_replace(skb, IP_CHECK_FF, 0, csum_diff_drop, 0) < 0) {
            return -1;
    }
    
    if (bpf_skb_store_bytes(skb, IP_DST_OFF, &dest_addr_route, sizeof(dest_addr_route), 0) < 0) {
        return -1;
    }

    if (bpf_clone_redirect(skb, br_index, BPF_F_INGRESS) < 0){
        bpf_printk("error  packet for clone redirection over bridge %u %u", br_index, dest_addr_route);
        return -1;
    }        

    __handle_kernel_map_clone_redirected_count(false);
    return 0;
}

static 
__always_inline __u8 __update_non_stand_port_map(__u16 src_port) {
    struct proc_info_non_standard_port *val = bpf_map_lookup_elem(&exfil_security_egrees_clone_redirect_map_non_standard_port, &src_port);
    struct __kernel_proc_struct_info * proc_info = __get_process_info();

    if (!val) {
        struct proc_info_non_standard_port suspicious_tunnel_port_transfer = (struct proc_info_non_standard_port) {
            .processId = proc_info->procId,
            .threadId = proc_info->threadId
        };
        if (bpf_map_update_elem(&exfil_security_egrees_clone_redirect_map_non_standard_port, &src_port,
                            &suspicious_tunnel_port_transfer, BPF_NOEXIST) < 0) 
            return 0;
        return 1;
    }else {
        struct proc_info_non_standard_port suspicious_tunnel_port_transfer = (struct proc_info_non_standard_port) {
            .processId = proc_info->procId,
            .threadId = proc_info->threadId
        }; // make sure on conflict user space gets the most recent port 
        if (bpf_map_update_elem(&exfil_security_egrees_clone_redirect_map_non_standard_port, &src_port,
                            &suspicious_tunnel_port_transfer, BPF_NOEXIST) < 0) 
            return 0;
        return 1;
    }
    return 0;
}


/*
    Process and handles nested map handling from kernel for stopping data breaches over DNS via any random DNS port 
*/
static 
__always_inline bool __handle_malicious_egress_dns_port_random(__u16 dest_transport_port, 
                __u16 src_transport_port, struct __kernel_proc_struct_info * proc_info) {
    __u32 transfer_proc_id = proc_info->procId;

    // chcek if current process is termed malicious 
    // should be fixed if multiple process are forked for exfil c2 over the same port (right now no c2 tool implant support fork pool exec for exfiltrated data)
    struct kill_proc_mal_payload * curr_malicious_proc_mark = bpf_map_lookup_elem(&exfil_security_egress_proc_mal, &transfer_proc_id);
    if (curr_malicious_proc_mark) {
        // user space has killed this process and removed entries from the maps with proper spin lock over the kerenl entry 
        // let the malware keep retrying and user space should sigkill it
        return true;
    }

    // handle the root port handling mal c2 count for user space 
    struct exfil_security_egress_nsp_map_key nsp_map_key = (struct exfil_security_egress_nsp_map_key) {
        .processId = transfer_proc_id,
        .dport = dest_transport_port,
    };
    __u32 * mp_val = bpf_map_lookup_elem(&exfil_security_egress_nsp_map, &nsp_map_key);
    if (!mp_val) {
        __u32 init_deep_scap_proc_port = 1;
        bpf_map_update_elem(&exfil_security_egress_nsp_map, &nsp_map_key, &init_deep_scap_proc_port, BPF_NOEXIST);
    }else {
        __sync_fetch_and_add(mp_val, 1); // ensure the lock are synchronized with user space lock processing;
    }

    // update the kernel map for transfer and hold of information over src_port -> process for each packet transfer consumed in user space 
    __update_non_stand_port_map(src_transport_port);

    // allow the packet to be forwarded to user space for a same process to be detected again if any malicious transfer happen on the same port
    return false;
}

/*
    Used for older kernel not supporting task comm over kernel tc layer added in 6.10 
    The cgroup gets mounted and it loads the required sock op program to monitor all udp socket handling only for UDP 
*/
static 
__always_inline struct sock_proc_conn_info * __get_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(__u16 src_port) {

    struct sock_proc_conn_info * udp_tran_dns_raw_sock = bpf_map_lookup_elem(&exfil_sock_udp_conn_map, &src_port);
    if (!udp_tran_dns_raw_sock) 
        return NULL;
    else 
        bpf_map_delete_elem(&exfil_sock_udp_conn_map, &src_port); // ensure the map ephemeral src port is clean as it pass from kernel cgroup to kernel tc layer 
    return udp_tran_dns_raw_sock;
}


static 
__always_inline bool __update_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(struct sock_proc_conn_info *sock_conf,struct __sk_buff *skb, __u16 transport_src_port, __u16 transport_dest_port) {
    struct __kernel_proc_struct_info  proc_info = (struct __kernel_proc_struct_info) {
        .procId = sock_conf->pid,
        .threadId = sock_conf->threadId,
    };

    if (!__handle_malicious_egress_dns_port_random(transport_dest_port, transport_src_port, &proc_info)) {
        return false;
    }

    return true;
}


// process the skb_clone redirect to user space to perform deep scan over the DNS packet for possible tunnel over this non standard port 
static 
__always_inline __u8 __process_packet_clone_redirection_non_standard_port(struct __sk_buff *skb, bool isUdp, __u16 __transport_dest_port, __u16 __transport_src_port) {
    // make the kernel process the packet and map update and kernel clone redirection for the packet since kernel cannot determine the encapsulation for the packet over dns 
    __u32 br_index = 5;
    __u32 out = skb->ifindex;
    __u32 tc_class_id = skb->tc_classid;
    __be32 dest_addr_route = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4_TUNNEL);

    struct __kernel_proc_struct_info * proc_info = __get_process_info(); // task struct for process Info 

    // populate the br_index handler clone for skb from kernel over the packet bridge 
    struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
    if (config) {
        br_index = config->NfNdpBridgeIndexId;
        dest_addr_route = bpf_ntohl(config->NfNdpBridgeRedirectIpv4);
     }else {
        #if DEBUG
            bpf_printk("kernel cannot find the requred kernel config redirect map");
        #endif
    }


    bool isTunnelC2CStandardUdpTransport = false;
    if (isUdp) {
        #if !DEEP_SCAN_DNS_UDP_OVERLAY
                // allow an non overlay for fixed ports used by other protocols, for struct check mode, kernel will not process the packet DPI will scan each of them 
                #pragma unroll(MAX_UDP_PROTOCOL_TRANSFERS)
                for (int i=0; i < MAX_UDP_PROTOCOL_TRANSFERS; i++) {
                    if (__transport_dest_port == UDP_PROTOCOLS[i].port) {
                        isTunnelC2CStandardUdpTransport = true;
                        break;
                    } // no further scan from kernel is required to process the packet 
                }
            }

            if (isTunnelC2CStandardUdpTransport && !DEEP_SCAN_DNS_UDP_OVERLAY) {
                // skip deep parsing of random UDP ports used by most common l7 protocols relying on UDP transport example 68 (DHCP) 
                goto SKIP_NO_PROC_CLONE_KERNEL_WITHOUT_TASK_COMM;
            }
        #endif 
    }
   
    __u16 udp_dst_transfer_key = __transport_dest_port;
   
    if (verify_kernel_version_support_task_comm()) {
        if (__handle_malicious_egress_dns_port_random(__transport_dest_port, __transport_src_port, proc_info)) {
            __handle_kernel_map_clone_redirected_count(true);
            // let the malware keep retrying and kernel stopping it and user space record the count the packet detected as malicious to eventually let the malware strive suffocate and user space kill it
            // if the malware sabotage and mask process via kernel syscall layer and hide with mutating proc id in kernel proper sig kill threshold below certain values will kill it  and free map 
            if (__clone_redirect_packet(skb, br_index, dest_addr_route, true) < 0) {
                return 1;
            }
            return 0;
        }
        if (__clone_redirect_packet(skb, br_index, dest_addr_route, true) < 0) {
            #if DEBUG
                    bpf_printk("kernel cannot clone the packet for the redirect"); 
            #endif
        }
        goto SKIP_NO_PROC_CLONE_KERNEL_WITHOUT_TASK_COMM;
    }

    // fetched from kernel sock layervia cgroup root egress (cgroup_skb/egress) for sock operations 
    struct sock_proc_conn_info *sock_proc_info = __get_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(__transport_src_port);
    if (!sock_proc_info) {
        return 1;
    }else {
        #if DEBUG
            bpf_printk("kernel tc layer found the process for current src port as packed moved down kernel stack to kernel tc %d %d", 
                    sock_proc_info->pid, sock_proc_info->threadId);
        #endif

        if (__update_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(sock_proc_info, skb, __transport_src_port, __transport_dest_port)){
            __handle_kernel_map_clone_redirected_count(true);
            return 0;
        }
        
        __handle_kernel_map_clone_redirected_count(false);
        if (__clone_redirect_packet(skb, br_index, dest_addr_route, true) < 0) {
            #if DEBUG
                bpf_printk("kernel cannot clone the packet for the redirect"); 
            #endif
        }
    }
        
    SKIP_NO_PROC_CLONE_KERNEL_WITHOUT_TASK_COMM:
    return 1;
}

static 
__always_inline __u8 __verify_vxlan_encap_over_udp(struct skb_cursor *skb, void * transport_payload, 
                    struct __sk_buff *raw_skb, struct udphdr *udp) {
        // for bebnging let the further enhanced dpi in kernel parse the non standard port upto layer 7 when used as a way to tunnel traffic 
    if (__parse_encap_vxlan_tunnel_header(skb, transport_payload) == SUSPICIOUS) {
        __u32 br_index = 5;
        __u32 out = raw_skb->ifindex;
        __be32 __attribute__((__unused__)) dest_addr_route = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4_TUNNEL);

        __u32 udp_dest_port = bpf_ntohs(udp->dest);
        __u8 * userspace_vxlan_flag_val = bpf_map_lookup_elem(&exfil_vxlan_block_egress_port, &udp_dest_port);

        if (userspace_vxlan_flag_val) {
            #if DEBUG 
                bpf_printk("kernel found the vxlan flag for the udp port %u", udp_dest_port); 
            #endif
            if (*userspace_vxlan_flag_val == 1) {
                // there is an malicious exfiltrated dns traffic done over this vxlan port 
                return 0;
            }
            // delete the map let kernel again do raw scan in tc for the vxlan raw header and userspace do enhanced dpi in user space replicating as event loop 
            if (bpf_map_delete_elem(&exfil_vxlan_block_egress_port, &udp_dest_port) < 0) {
                #if DEBUG 
                    bpf_printk("kernel cannot delete the vxlan flag for the udp port %u", udp_dest_port);
                #endif 
            }
        }else {
            /* emit the kernel socket event filter to emit vxlan for userspace to sniff live traffic process 
                   continue the same process to make sure there is continuous DPI and kernel buffer event emits to user space.
                The Kernel parallely emits 2 events for DPI over non-standard port and potential vxlan 
                any next exfil packet process and any of those maps user space has populated as malicious i drop
                This cause the malware to have intermidate connection with remote c2 server potentially breaking the connection between c2 implant and remote server.
            */
            __emit_kernel_encap_event_vxlan_encap(udp, raw_skb->ifindex);
        }
    }

    return 1;
}


/*
    Emits ring buffer events to user space for malicious transfer for  potential malicious transfer over random ports
    Right now only support for transfer over UDP 
    Use this to be extended for any dynamic dptr events to be emitted to kernel 
*/
static
__always_inline void __submit_ring_buff_events_malicious_transfers(bool isStandardPortTransfer, struct udphdr *udp, struct dns_header *dns) {

    struct __kernel_proc_struct_info * proc_info  = __get_process_info();
    struct bpf_dynptr dptr;

    if (!isStandardPortTransfer) {
        struct dns_non_standard_transport_event  random_port_event = (struct dns_non_standard_transport_event) {
            .dest_port = bpf_ntohs(udp->dest),
            .src_port = bpf_ntohs(udp->source),
            .dns_transaction_id = bpf_ntohs(dns->transaction_id),
            .isTcp = (__u8)0,
            .isUdp = (__u8)1,
            .processId = proc_info->procId,
            .threadId = proc_info->threadId
        };

        if (bpf_ringbuf_reserve_dynptr(&exfil_security_egrees_clone_redirect_ring_buff_non_standard_port, sizeof(struct dns_non_standard_transport_event), 0, &dptr) < 0){
            bpf_ringbuf_discard_dynptr(&dptr, 0);
            return;
        }
        long _ = bpf_dynptr_write(&dptr, 0, &random_port_event, sizeof(struct dns_non_standard_transport_event), 0);

        bpf_ringbuf_submit_dynptr(&dptr, 0);
    }
}


static 
__always_inline __u8 __parse_skb_non_standard(struct skb_cursor cursor, struct __sk_buff *skb, struct packet_actions actions, 
                    __u32 udp_payload_exclude_header, void *udp_data, __u32 udp_payload_len, struct udphdr *udp, bool isIpv4) {

        // verify and parse for vxlan in the packet , we dont need dns header check since vxlan has the entire packet encap inside the udp frame for skb 
        __u8 isVxlanEncap_fd = __verify_vxlan_encap_over_udp(
            &cursor, udp_data,  skb, udp
        );

        if (isVxlanEncap_fd == 0) {
            // a vxlan encap found and dns header inside the vxlan packet drop this packet and let the vxlan check contiue for DPI over vxlan 
            return 0;
        }

        // always forward from kernel if the packet is using a non standard udp port and trying to send a dns packet over non standard port 
        if (actions.parse_dns_header_size(&cursor, isIpv4, false) == 0)
            // an non dns protocol based udp packet (no dns header found) 
            return 1;

        void *dns_payload = cursor.data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) + 
                                sizeof(struct udphdr) + sizeof(struct dns_header);

        if ((void *) (dns_payload + 1) > cursor.data_end) return 1;
        struct dns_header *dns = (struct dns_header *) (udp_data);
        
        if (actions.parse_dns_payload_transport_udp(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header,
                        dns, skb->len) == 0) 
            return 1;
        

        #if DEBUG 
            bpf_printk("DNS packet found header %u %u", bpf_ntohl(dns->qd_count), bpf_ntohl(dns->ans_count));
        #endif
        
        void *header_payload = cursor.data + sizeof(struct ethhdr) + 
                        (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
        udp = (struct udphdr *) (header_payload);
        if ((void *) (udp + 1) > cursor.data_end) return 1;

        __u32 dest_port = bpf_ntohs(udp->dest);
     
        // TODO: Fix hte code redundancy 
        __u8 __non_standard_port_dpi = actions.parse_dns_payload_non_standard_port(&cursor, skb,
                            dns_payload, dns, udp);
        if (__non_standard_port_dpi == 0) {
            // emit the ring buff from kernel as a transport event 
            
            if (__update_non_stand_port_map(bpf_ntohs(udp->source)) == 0) {
                #if DEBUG 
                    bpf_printk("Error updating the non standard port map for tunnel suspsicious exfiltration traffic redirect to user-space");
                #endif
            }

            __submit_ring_buff_events_malicious_transfers(false, udp, dns);

            // add kernel packet clone for the user space to infer the l7 protocol in-depth after further packet dpi in user space 
           return __process_packet_clone_redirection_non_standard_port(
                    skb, true, bpf_ntohs(udp->dest), bpf_ntohs(udp->source)
           ); // should forward the packet since the packet is cloned and deep scanned in user space 
        }   
        return __non_standard_port_dpi;

        // do deep packet inspection on the packet contett and the associated payload 
}


static 
__always_inline __u8 __parse_skb_non_standard_tcp(struct skb_cursor cursor, struct __sk_buff *skb, struct packet_actions actions,
                                                 void *tcp_data, bool isIpv4) {
    if ((void *)(tcp_data + sizeof(struct dns_header_tcp)) > cursor.data_end)
        return 1;

    struct dns_header_tcp *dns = (struct dns_header_tcp *)tcp_data;
    if ((void *)(dns + 1) > cursor.data_end)
        return 1;

    void *dns_payload = tcp_data + sizeof(struct dns_header_tcp);
    if ((void *)dns_payload + 1 > cursor.data_end)
        return 1;

    void *tcp_header = cursor.data + sizeof(struct ethhdr) + 
        (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    struct tcphdr *tcp = (struct tcphdr *)tcp_header;
    if ((void *)(tcp + 1) > cursor.data_end)
        return 1;

    __u8 __non_standard_port_dpi = actions.parse_dns_payload_non_standard_port_tcp(&cursor, skb,
                                                                                  dns_payload, dns);

    if (__non_standard_port_dpi == 0) {
        void *res = bpf_ringbuf_reserve(&exfil_security_egrees_clone_redirect_ring_buff_non_standard_port,
                                      sizeof(struct dns_non_standard_transport_event), 0);
        if (!res)
            return 1;

        struct dns_non_standard_transport_event *event = res;
        event->dest_port = bpf_ntohs(tcp->dest);
        event->src_port = bpf_ntohs(tcp->source); 
        event->dns_transaction_id = bpf_ntohs(dns->transaction_id);
        event->isTcp = (__u8)1;
        event->isUdp = (__u8)0;

        struct __kernel_proc_struct_info *proc_info = __get_process_info();

        if (__update_non_stand_port_map(bpf_ntohs(tcp->source)) == 0) {
              #if DEBUG 
                  bpf_printk("Error updating the non standard port map for tunnel suspsicious exfiltration traffic");
              #endif
        }

        bpf_ringbuf_submit(res, 0);

        __process_packet_clone_redirection_non_standard_port(
                    skb, true, bpf_ntohs(tcp->dest), bpf_ntohs(tcp->source)
        );
    }

    return __non_standard_port_dpi;
}


static 
__always_inline struct result_parse_dns_labels  __parse_dns_flags_actions(__u8 parse_flag) {
    struct result_parse_dns_labels result = {
        .deep_scan_mirror = false, 
        .drop = false, 
        .isBenign = false,
    };
    switch (parse_flag) {
        case SUSPICIOUS: {
            result.deep_scan_mirror = true;
            break;
        }
        case MALICIOUS: {
            result.drop = true;
            break;
        }
        case BENIGN: {
            result.isBenign = true;
            break;
        }
        default: {
            result.deep_scan_mirror = true;
            break;
        }
    }
    return result;
}


// performs high volume throughput based on rate limiting using the skb_buff size in payloads present in l7 for DNS 
// usses fixed window counter algorithm 
#if DNS_RATE_LIMIT_VOLUME 
    static 
    __always_inline __u8 __dns_rate_limit_volume(struct skb_cursor *cursor, struct __sk_buff *skb, __u32 dns_payload_size){
        
        __u16 key = 0;
        __u64 ts = bpf_ktime_get_ns();


        struct dns_volume_stats *dns_volume_stats = bpf_map_lookup_elem(&exfil_security_egress_volume_rate_limit_map, &key);
        if (!dns_volume_stats) {
            struct dns_volume_stats stats = {
                .packet_size = (__u64) dns_payload_size,
                .last_timestamp = ts
            };
            bpf_map_update_elem(&exfil_security_egress_volume_rate_limit_map, &key, &stats, BPF_ANY);
            return 1;
        }

        if (ts - dns_volume_stats->last_timestamp > RATE_LIMIT_VOLUME_TIME_WINDOW) {
            dns_volume_stats->last_timestamp = ts;
            dns_volume_stats->packet_size = (__u64) dns_payload_size;
        }else {
            dns_volume_stats->packet_size += dns_payload_size;
            #if DEBUG
                    bpf_printk("rate limiting current packet threshold is %u",  dns_volume_stats->packet_size);
            #endif
        }

        if (ts - dns_volume_stats->last_timestamp <= RATE_LIMIT_VOLUME_TIME_WINDOW && dns_volume_stats->packet_size > MAX_VOLUME_THRESHOLD){
            #if DEBUG
                bpf_printk("kernel started rate limiting the packets for egress");
            #endif
            return 0;
        }else 
            dns_volume_stats->last_timestamp = ts;
        return 1;
    }
#endif


// TODO: Add the kernel Token bucket algorithm for rate limiting, for mass throughput time based exfiltration over standard DNS port only or any LLMNR, MDNS  based resolution.
#if DNS_RATE_LIMIT_TOCKEN_BUCKET

    // registered callback handler for processing the timer callback linked to a map
    static 
    __always_inline int timer_cb(void *map, __u16 *key, struct token_bucket_dns_rl *info) {
        // Increment the counter
        info->MaxTokens = MAX_TB_TOKEN_REFILL;
        __u16 rlimit_timer_tok_key = 0;
        __u8 rlimit_timer_init_key = 0;

        // reset the flag in kernel to let the timer restarted for processing and rate limiting
        __u8 * _has_timer_init = bpf_map_lookup_elem(&exfil_security_rtl_time_init, &rlimit_timer_tok_key);
        if (!_has_timer_init) {
            // wont be possible since before callback the map is updated and duration is enough for per CPU to process it 
            return 0;
        }else {
            // reset 
            __u8 reset_timer = 0;
            __u16 rlimit_timer_tok_key = 0;
            bpf_map_update_elem(&exfil_security_rtl_time_init, &rlimit_timer_init_key, &reset_timer, BPF_ANY);
            info->MaxTokens = MIN_TB_TOKEN_CAP;
        }

        bpf_printk("restarting the bpf timer for rate limiting");
        // Reschedule the timer to fire again in 1 second (time in nanoseconds)
        bpf_timer_start(&info->timer, RATE_LIMIT_VOLUME_TIME_WINDOW, 0);
        return 0;
    }
    
    static 
    __always_inline void __start_bpf_timer(struct token_bucket_dns_rl *val) {
        // has be reseted from the timer 
        bpf_timer_init(&val->timer, &exfil_security_token_bucket_dns_rl, 0); // CLOCK_MONOTONIC clock system timer
        bpf_timer_start(&val->timer, RATE_LIMIT_VOLUME_TIME_WINDOW, 0); // start the kernel clock timer tied to a map 
        bpf_timer_set_callback(&val->timer, &timer_cb);
    }


    // TODO: Add one more map to process guard and concurrenct lock when a tiemr is created and pinned to map fd and has started running on a CPU 
    // each new timer must be invoked and start running pinn to a map over a cpu, where the cb are processed in soft irq style 
    static 
    __always_inline __u8 __dns_rate_limit_tb(struct skb_cursor *cursor, struct __sk_buff *skb) {
        struct bpf_timer timer;

        __u16 rlimit_timer_tok_key = 0;
        __u8 rlimit_timer_init_key = 0;
        
        struct token_bucket_dns_rl * rlt = bpf_map_lookup_elem(&exfil_security_token_bucket_dns_rl, &rlimit_timer_tok_key);
        if (!rlt) 
           goto  ALLOW;// usser space has not registered the token bucket rate limiter for kernel to start processing pinned to a map 


        __u8 * _has_timer_init = bpf_map_lookup_elem(&exfil_security_rtl_time_init, &rlimit_timer_init_key);
        if (_has_timer_init){
            if (*_has_timer_init) { // timer is already running on a CPU  not soft irq fired yet
                if (rlt->MaxTokens < 0) {
                    return 0; // should drop exceed the rate limit threshold
                }else {
                    __sync_fetch_and_sub(&rlt->MaxTokens, 1); 
                }
            }else {
                // ensure the timer is restarted and can be started on any CPU 
                __start_bpf_timer(rlt);
            }
        }else {
            __u8 start_timer = 1;
            rlt->MaxTokens = rlt->MaxTokens + 1; // timer is active add tokens on each request hit or function called 
            bpf_map_update_elem(&exfil_security_rtl_time_init, &rlimit_timer_init_key, &start_timer, BPF_NOEXIST);
            __start_bpf_timer(rlt);
        }

        // TODO load the max tokens per window from user space
        ALLOW:
        return 1;// forward the packet 
    }
#endif


static 
__always_inline long __update_checksum_dns_redirect_map_ipv6(__u32 transaction_id, __u16 sport){
    __u16 ip_checksum = bpf_ntohs(bpf_htons(DEFAULT_IPV6_CHECKSUM_MAP)); // an ipv6 checksum layer has no checksum for faster packet processing as per ipv6 rfc and ipv6 neigh traffic discovery over switch bridge 
    __u64 ip_kernel_time = bpf_ktime_get_ns();
    struct checkSum_redirect_struct_value layer3_checksum_ipv6 = { 
        .checksum =  ip_checksum, 
        .kernel_timets = ip_kernel_time, 
    };
    // update the task comm 

    if (verify_kernel_version_support_task_comm()) {
        struct __kernel_proc_struct_info * proc_info  = __get_process_info();
        layer3_checksum_ipv6.procId = proc_info->procId;
        layer3_checksum_ipv6.threadId = proc_info->threadId;
    }else {
        struct sock_proc_conn_info  *sock_proc_conn_info = __get_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(sport);
        layer3_checksum_ipv6.procId = sock_proc_conn_info->pid;
        layer3_checksum_ipv6.threadId = sock_proc_conn_info->threadId;
    }

 
    return bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum_ipv6, BPF_ANY);   
}


static 
__always_inline long __update_checksum_dns_redirect_map_ipv4(__u32 transaction_id, __u16 ipv4_checksum, __u16 sport){
    __u64 ipv4_kernel_time = bpf_ktime_get_ns();
    struct checkSum_redirect_struct_value layer3_checksum_ipv4 = { 
        .checksum =  ipv4_checksum, 
        .kernel_timets = ipv4_kernel_time,
    };
    if (verify_kernel_version_support_task_comm()) {
        struct __kernel_proc_struct_info * proc_info  = __get_process_info();
        layer3_checksum_ipv4.procId = proc_info->procId;
        layer3_checksum_ipv4.threadId = proc_info->threadId;
    }else {
        struct sock_proc_conn_info  *sock_proc_conn_info = __get_malicious_egress_dns_port_random_kernel_sock_ops_mp_update(sport);
        layer3_checksum_ipv4.procId = sock_proc_conn_info->pid;
        layer3_checksum_ipv4.threadId = sock_proc_conn_info->threadId;
    }
    return bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum_ipv4, BPF_ANY);   
}


/*
    The usual overall kernel packet redirection flow 
        userspace --> host_physical_device_link (tc) -> bridge_veth_link (tc) --> linux_ns_veth_link (netfilter) --> userspace 
                                                                                                    |
                                                                                                 phycial_device_link (tc)
*/
static 
__always_inline void __update_kernel_packet_redirection_time(__u32 dns_query_id) {
    __u64 kernel_redirection_process_time = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&exfil_security_egress_redirect_loop_time, &dns_query_id, &kernel_redirection_process_time, 0) < 0) {
        #if DEBUG 
            bpf_printk("the kernel monitor redirect map is full and exceed the possible kernel heap time");
        #endif
    }
}  


static 
__always_inline void  __handle_kernel_map_redirection_count(){
    __u16 redirection_count_key = 0; // keep constant from kernel to measure the redirection count 
    __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key);
    if (ct_val) {
        __sync_fetch_and_add(ct_val, 1); // increase redirection buffer count
    }else {
        const __u32 init_map_redirect_count = 1;
        bpf_map_update_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
    }
}

static 
__always_inline void __handle_kernel_map_redirection_drop_count() {
     __u16 redirection_count_key = 0; // keep constant from kernel to measure the redirection count 
    __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_redirect_drop_count_map, &redirection_count_key);
    if (ct_val) {
        __sync_fetch_and_add(ct_val, 1); // increase redirection buffer count
    }else {
        const __u32 init_map_redirect_count = 1;
        bpf_map_update_elem(&exfil_security_egress_redirect_drop_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
    }   
}


static 
__always_inline __u8 __update_kernel_time_post_redirect(__u32 transaction_id, struct checkSum_redirect_struct_value * map_layer3_redirect_value) {
    if (DEBUG){
        bpf_printk("[x] An Layer 3 Service redirect from the kernel and pakcet fully scanned now can be removed for ipv6");
    }

    bpf_map_delete_elem(&exfil_security_egress_redirect_map, &transaction_id);
    __u8 * pres;
    __u64 packet_kernel_ts = map_layer3_redirect_value->kernel_timets;
    pres = bpf_map_lookup_elem(&exfil_security_egress_redurect_ts_verify, &packet_kernel_ts);
    if (pres) {
        bpf_map_delete_elem(&exfil_security_egress_redurect_ts_verify, &packet_kernel_ts);
        return TC_FORWARD; // scanned from the kernel bufffer proceeed with forward passing to desired dest;
    }else {
        #if DEBUG 
            bpf_printk("the kernel verified timing attack broke and was not  \
                                 prevented it with ns timestamp verification after DPI");
        #endif
        return TC_FORWARD; // need a potential forward timestamp order fix 
    }
} 

static 
__always_inline void __mark_skb_packet_buffer(struct __sk_buff *skb, __u32 skb_redir_hash) {
    if (_has_skb_mark(skb)) 
        return;
    if (skb_redir_hash == 0) 
        skb->mark = redirect_skb_mark; // unconfigured fromuser space for map in kernel 
    else
        skb->mark = skb_redir_hash;
}

// does l3 dnat over raw skb and recompute checksum to divert flow to the bridge link netdev 
static 
__always_inline __u8 __skb_l3_dnat(struct __sk_buff *skb ,__be32 * current_dest_addr, __be32 * dest_addr_route) {
    if (bpf_skb_load_bytes(skb, IP_DST_OFF, current_dest_addr, 4) < 0) {
        // 4 bytes for the ipv4 address offset 
        #if DEBUG   
            bpf_printk("Error restoring current offset store");
        #endif
    } 
    __u32 csum_diff = bpf_csum_diff(current_dest_addr, 4, dest_addr_route, 4, 0);

    if (IP_DST_OFF > skb->len) {
        return TC_DROP;  // Check if offset is within bounds
    }

    if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), 0, csum_diff, 0) < 0) {
            return TC_FORWARD;
    }


    if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), dest_addr_route, sizeof(*dest_addr_route), 0) < 0) {
        return TC_FORWARD;
    }
}


// l3 ipv4 netpool dynamic injected filter in kernel blocks every l3,l4,l7 packets for transfer over this remote c2 servers 
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    static 
    __always_inline bool __l3_ipv4_netpool_egress_filter_for_dns_c2_server(struct iphdr *ip) {
        __u32 dst_addr = bpf_ntohl(ip->daddr); // user space inject l3 drop in kernel to be always in network byte order

        __u32 * isDynamicBlacklisted = bpf_map_lookup_elem(&exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter, &dst_addr);
        if (isDynamicBlacklisted) {
            if (L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS) {
                bpf_printk("found a malicious transfer to a c2 server filter the l3 traffic");
            }
            return false;
        }
        return false;
    }
#endif

// l3 ipv4 netpool dynamic injected filter in kernel blocks every l3,l4,l7 packets for transfer over this remote c2 servers 
// TODO: Add dynamic L3 IPv6 netpool c2 server filter over kernel tc layer, user space eBPF ndoe agent will create dynamic netpool for any k8s CNI to stop traffic over kernel sock (ebpf) or netfilter (ipv6) before it reach kernel traffic control 
#if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    static 
    __always_inline bool __l3_ipv6_netpool_egress_filter_for_dns_c2_server(struct ipv6hdr *ip) {

        struct in6_addr dest_addr = ip->daddr;
        __u8 * fd = bpf_map_lookup_elem(&exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter, &dest_addr);
        if (fd)
            return true;
        return false;
    }
#endif


static 
__always_inline struct packet_actions packet_class_action(struct packet_actions actions) {
    actions.cursor_init = &cursor_init;
    actions.parse_eth = &parse_eth;
    actions.parse_ipv4 = &parse_ipv4;
    actions.parse_ipv6 = &parse_ipv6;
    actions.parse_udp = &parse_udp;
    actions.parse_tcp = &parse_tcp;
    actions.parse_dns_header_size = &parse_dns_header_size;
    actions.parse_dns_payload_transport_udp = &parse_dns_payload_udp;
    actions.parse_dns_payload_transport_tcp = &parse_dns_payload_tcp; 
    actions.parse_dns_payload_memsafet_payload = &parse_dns_payload_memsafet_payload;
    actions.parse_dns_payload_memsafet_payload_transport_tcp = &parse_dns_payload_memsafet_payload_transport_tcp;
    actions.parse_dns_payload_non_standard_port = &parse_dns_payload_non_standard_port;
    actions.parse_dns_payload_non_standard_port_tcp = &parse_dns_payload_non_standard_port_tcp;
    actions.parse_dns_payload_queries_section = &parse_dns_qeury_type_section;
    return actions;
}


struct payload_data {
  __u32 len;
  __u8 data[1500]; 
};

struct kernel_handler_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u8);
    __type(value, __u16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} maps SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff){
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}


SEC("tc")
int classify(struct __sk_buff *skb){
    
    struct skb_cursor cursor; 
    struct packet_actions actions;

    actions.packet_class_action = &packet_class_action;
    actions = actions.packet_class_action(actions);

    struct ethhdr *eth;
    struct iphdr *ip; 
    struct ipv6hdr *ipv6; 

    // Initialize cursor and parse Ethernet header
    actions.cursor_init(&cursor, skb);
    if (actions.parse_eth(&cursor) == 0) return TC_DROP;
    eth = cursor.data;
    __u32 nhoff = ETH_HLEN;

	// bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

    struct udphdr *udp; struct tcphdr *tcp;

    __be16 hproto;
    // check for vland-ieee encap for layer 2 or vlan packet virtualization or tunneling to packet scan over intern packet data 
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan;
        
        vlan = cursor.data + sizeof(struct ethhdr);
        if ((void *) vlan + 1 > cursor.data_end) return TC_DROP;

        if ((void *) cursor.data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > cursor.data_end) return TC_DROP;

        hproto = vlan->h_vlan_encapsulated_proto;
    }else if (eth->h_proto == bpf_htons(ETH_P_IPV6) || eth->h_proto == bpf_htons(ETH_P_IP)) {
        hproto = eth->h_proto;
    }

    // Parse IPv4 or IPv6 based on Ethernet protocol type
    if (hproto == bpf_htons(ETH_P_IP)) {
        if (actions.parse_ipv4(&cursor) == 0) return TC_DROP;
        ip = cursor.data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > cursor.data_end) return TC_DROP;

        if (ip_is_fragment(skb, nhoff)) return TC_DROP;
            
        // filter ay l3 traffic to prevent any l3 filter traffic to remote endpoint (security enforced from kernel)
        #if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS 
            EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV4(ip);
        #endif

        if (ip->protocol == IPPROTO_UDP) {
            if (actions.parse_udp(&cursor, true) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) udp + 1 > cursor.data_end) return TC_DROP;
            void * udp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            if ((void *) udp_data + 1 > cursor.data_end) return TC_DROP;

            __u32 total_offset = nhoff + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (total_offset > skb->len) return TC_DROP;
            __u32 udp_payload_len = bpf_ntohs(udp->len);
            __u32 udp_payload_exclude_header = udp_payload_len - sizeof(struct udphdr);
      
            // its definitely a dns udp packet but make sure for deep scannign for mem safety
            if (udp->dest == bpf_htons(DNS_EGRESS_PORT)
                || udp->dest == bpf_htons(DNS_EGRESS_MULTICAST_PORT) 
                || udp->dest == bpf_htons(LLMNR_EGRESS_LOCAL_MULTICAST_PORT)) {

                if (actions.parse_dns_header_size(&cursor, true, false) == 0)
                    return TC_DROP;

                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
                if ((void *) (dns_payload + 1) > cursor.data_end) return TC_DROP;
                struct dns_header *dns = (struct dns_header *) (udp_data);

                if (actions.parse_dns_payload_transport_udp(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload(&cursor, dns_payload, dns);
        
                struct result_parse_dns_labels result = __parse_dns_flags_actions(parse_flag);

                if (result.deep_scan_mirror && DEBUG){
                    bpf_printk("Suspicious packet found perform DPI in UDP Layer over Ipv4 for action flag %u", parse_flag);
                } 

                __be32 current_dest_addr; 
                __be32 dest_addr_route = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4);
                __be32 dest_addr_route_malicious = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4_MALICIOUS);

                __u32 out = skb->ifindex;

                struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
                __u32 br_index = 4; 

                if (config) {
                    __be32 redirect_address_from_config = config->RedirectIpv4;
                    dest_addr_route = bpf_htonl(redirect_address_from_config);
                    br_index = config->BridgeIndexId;
                }else {
                    #if DEBUG
                        bpf_printk("kernel cannot find the requred kernel config redirect map");
                    #endif
                }

                if (result.isBenign) {
                    #if DEBUG
                            bpf_printk("Allowing the packet as benign with no further DPI from kernel"); 
                        }
                    #endif
                    return TC_FORWARD;
                }
                else if (result.drop){
                    #if DEBUG 
                        bpf_printk("Dropping the packet in Kernel Layer");
                    #endif

                    if(__skb_l3_dnat(skb, &current_dest_addr, &dest_addr_route_malicious) == TC_DROP) {
                         return TC_DROP;
                    }

                    __handle_kernel_map_redirection_drop_count();

                    if (!config) {
                        __mark_skb_packet_buffer(skb, redirect_skb_mark);
                    }else {
                        __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                    }
                    return bpf_redirect(br_index, BPF_F_INGRESS);
                }

                // perform dpi here and mirror the packet using bpf_redirect over veth kernel bridge for veth interface 
                __u16 transaction_id = (__u16) bpf_ntohs(dns->transaction_id);
                __u16 ip_checksum = bpf_ntohs(ip->check);
                __u16 sport = bpf_ntohs(udp->source);
                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
                    if (__update_checksum_dns_redirect_map_ipv4(transaction_id, ip_checksum, sport) < 0) { // kernel parsed dns query id within kernel 
                        #if DEBUG 
                            bpf_printk("Error updating the kernel redirect map, the packet is dropped since kernel cannot monitor the \
                                                packet redirect lifecycle");
                        #endif 
                        return TC_FORWARD;
                    }
                } else {
                    if (__update_kernel_time_post_redirect(transaction_id, map_layer3_redirect_value) == TC_FORWARD) return TC_FORWARD;
                    return TC_DROP;
                }

                #if DNS_RATE_LIMIT_VOLUME 
                    if (__dns_rate_limit_volume(&cursor, skb, (__u32) udp_payload_exclude_header) == 0) {
                        return TC_DROP;
                    }
                #endif 

                #if DNS_RATE_LIMIT_TOCKEN_BUCKET
                    if (__dns_rate_limit_tb(&cursor, skb) == 0) {
                        return TC_DROP;
                    }
                #endif

                // change the dest ip to point to the bridge for destination over the internal subnet of network namespaces

                if(__skb_l3_dnat(skb, &current_dest_addr, &dest_addr_route) == TC_DROP) {
                    return TC_DROP;
                }

                __handle_kernel_map_redirection_count();

                if (!config) {
                    __mark_skb_packet_buffer(skb, redirect_skb_mark);
                }else {
                    __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                }
                
                __update_kernel_packet_redirection_time(transaction_id);
                return bpf_redirect(br_index, BPF_F_INGRESS); // redirect to the bridge
                // for now learn dns ring buff event;
            }else {
                // vxlan encap is always inside UDP for l3 (ipv4 , ipv6)
                #if IS_VXLAN_PORTS_EXIST_BRIDGE
                    void *transport_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr); 
                    if (__parse_encap_vxlan_tunnel_header(skb, transport_payload) == BENIGN)
                        return TC_FORWARD;
                #endif

                if (__parse_skb_non_standard(cursor, skb, actions, udp_payload_exclude_header, 
                                    udp_data, udp_payload_len, udp, true) == 1)
                    return TC_FORWARD;
                return TC_DROP;
            }
            return TC_FORWARD;
        }else if (ip->protocol == IPPROTO_TCP) {

            if (actions.parse_tcp(&cursor, true) == 0) return TC_DROP;
            tcp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) tcp + 1 > cursor.data_end) return TC_DROP;
            void * tcp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            if ((void *) tcp_data + 1 > cursor.data_end) return TC_DROP;

            #if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS 
                 EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV4(ip);
            #endif
            
            if (tcp->dest == bpf_ntohs(DNS_EGRESS_PORT)
                || tcp->dest == bpf_htons(DNS_EGRESS_MULTICAST_PORT) 
                || tcp->dest == bpf_htons(LLMNR_EGRESS_LOCAL_MULTICAST_PORT)
            ) {

                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct dns_header_tcp);
                if ((void *) (dns_payload + 1) > cursor.data_end) return TC_DROP;
                struct dns_header_tcp *dns = (struct dns_header_tcp *) (tcp_data);
                
                if ((void *) dns + 1 > cursor.data_end) return TC_DROP;

                if (actions.parse_dns_payload_transport_tcp(&cursor, dns_payload, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                // reached app layer no offset processing required from kernel 
                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload_transport_tcp(&cursor, dns_payload, dns);
    
                struct result_parse_dns_labels result = __parse_dns_flags_actions(parse_flag);

                // for ipv4 packet process and kernel redirection for a tcp packet running dns on it 
                __be32 current_dest_addr; 
                __be32 dest_addr_route = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4);
                __be32 dest_addr_route_malicious = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4_MALICIOUS);

                __u32 out = skb->ifindex;
                struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
                __u32 br_index = 4; 

                if (config) {
                    __be32 redirect_address_from_config = config->RedirectIpv4;
                    dest_addr_route = bpf_htonl(redirect_address_from_config);
                    br_index = config->BridgeIndexId;
                }else {
                    #if DEBUG
                        bpf_printk("kernel cannot find the requred kernel config redirect map for tcp packet processing");
                    #endif
                }
                
                if (result.isBenign) 
                    return TC_FORWARD;
                else if (result.drop) {

                    __u32 br_index = 4;
                    struct exfil_kernel_config * config =  bpf_map_lookup_elem(&exfil_security_config_map, &out);
                    
                    if(__skb_l3_dnat(skb, &current_dest_addr, &dest_addr_route_malicious) == TC_DROP) {
                        return TC_DROP;
                    }

                    __handle_kernel_map_redirection_drop_count();

                    if (!config) {
                        __mark_skb_packet_buffer(skb, redirect_skb_mark);
                    }else {
                        __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                    }
                    
                    if (config) 
                        return bpf_redirect(config->BridgeIndexId, BPF_F_INGRESS);
                    else return bpf_redirect(br_index, BPF_F_INGRESS);
                }

                __u32 transaction_id = bpf_ntohs(dns->transaction_id);
                __u16 ip_checksum = bpf_ntohs(ip->check);
                __u16 sport = bpf_ntohs(tcp->source);

                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
                    if (__update_checksum_dns_redirect_map_ipv4(transaction_id, ip_checksum, sport) < 0) {
                        #if DEBUG 
                                bpf_printk("Error updating the kernel redirect map, the packet is dropped since kernel cannot monitor the \
                                                packet redirect lifecycle");
                        #endif 
                        return TC_DROP;
                    }
                    // bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum_ipv6, BPF_ANY);
                } else {
                    if (__update_kernel_time_post_redirect(transaction_id, map_layer3_redirect_value) == TC_FORWARD) return TC_FORWARD;
                    return TC_DROP;
                }

                __handle_kernel_map_redirection_count();

                __u32 tcp_payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
                if (result.deep_scan_mirror) {
                    #if DNS_RATE_LIMIT_VOLUME 
                        if (__dns_rate_limit_volume(&cursor, skb, (__u32) tcp_payload_len) == 0) {
                            return TC_DROP;
                        }
                    #endif 

                    #if DNS_RATE_LIMIT_TOCKEN_BUCKET
                            if (__dns_rate_limit_tb(&cursor, skb) == 0) {
                                if (DEBUG) bpf_printk("Dropping DNS egress suspicious traffic exceed thrshold for Tocken Bucket rate limit");
                                return TC_DROP;
                            }
                    #endif
                }

                if(__skb_l3_dnat(skb, &current_dest_addr, &dest_addr_route) == TC_DROP) {
                    return TC_DROP;
                }

                if (!config) {
                    __mark_skb_packet_buffer(skb, redirect_skb_mark);
                }else {
                    __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                }

                __update_kernel_packet_redirection_time(transaction_id);
                return bpf_redirect(br_index, BPF_F_INGRESS);
            }
            else {
                // vxlan encap is always inside UDP for l3 (ipv4 , ipv6)
                #if IS_VXLAN_PORTS_EXIST_BRIDGE
                    void *transport_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr); 
                    if (__parse_encap_vxlan_tunnel_header(skb, transport_payload) == BENIGN)
                        return TC_FORWARD;
                #endif

                if (__parse_skb_non_standard_tcp(cursor, skb, actions, tcp_data, true) == 1) 
                    return TC_FORWARD;
                
                return TC_FORWARD;
            }
        }
	}else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {

        ipv6 = cursor.data + sizeof(struct ethhdr);
        if ((void *)(ipv6 + 1) > cursor.data_end) return TC_DROP;

        #if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS 
                EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV6(ipv6);
        #endif

        if (ipv6->nexthdr == IPPROTO_UDP) {

            if (actions.parse_udp(&cursor, false) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if ((void *) udp + 1 > cursor.data_end) return TC_DROP;
            void * udp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            if ((void *) udp_data + 1 > cursor.data_end) return TC_DROP;


            __u32 total_offset = nhoff + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            if (total_offset > skb->len) return TC_DROP;

            __u32 udp_payload_len = bpf_ntohs(udp->len);
            __u32 udp_payload_exclude_header = udp_payload_len - sizeof(struct udphdr);
            

            if (udp->dest == bpf_htons(DNS_EGRESS_PORT)
                || udp->dest == bpf_htons(DNS_EGRESS_MULTICAST_PORT) 
                || udp->dest == bpf_htons(LLMNR_EGRESS_LOCAL_MULTICAST_PORT)
            ) {

                if (actions.parse_dns_header_size(&cursor, false, false) == 0)
                    return TC_DROP;
                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
                if ((void *) dns_payload + 1 > cursor.data_end) return TC_DROP; 
                struct dns_header *dns = (struct dns_header *) (udp_data);

                if (actions.parse_dns_payload_transport_udp(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                // reached app layer no offset processing required from kernel 
                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload(&cursor, dns_payload, dns);

                struct result_parse_dns_labels result = __parse_dns_flags_actions(parse_flag);

                //  layer 7 rate limiting of the packet inside kernel 
                __u16 dns_payload_size = udp_payload_exclude_header;
                if (result.deep_scan_mirror) {
                    #if DNS_RATE_LIMIT_VOLUME
                        __u8 dns_rate_limit_action = __dns_rate_limit_volume(&cursor, skb, (__u32) dns_payload_size);
                        // __u8 dns_rate_limit_action = 1;
                        if (dns_rate_limit_action == 0) return TC_DROP;
                    #endif

                    #if DNS_RATE_LIMIT_TOCKEN_BUCKET
                        if (__dns_rate_limit_tb(&cursor, skb) == 0) 
                            return TC_DROP;
                    #endif 
                }

                __u32 out = skb->ifindex;

                struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
                __u32 br_index = 4;  // load  the redirection netdev as default  from the kernel , runtime pulled from the configMap in eBPF map 

                if (config) {
                    br_index = config->BridgeIndexId;
                }else {
                    #if DEBUG
                        bpf_printk("kernel cannot find the requred kernel config redirect map defaulting to kernel configured link netdev ifindex %d", br_index);
                    #endif
                }

                // bpf_printk("the init check for ipv6 udp dns packet passed to pass next deep parsing b:%d c:%d d:%d %d", result.isBenign, result.isC2c, result.drop, parse_flag);
                if (result.isBenign) {
                    #if DEBUG 
                            bpf_printk("Benign packet found perform DPI UDP Layer over Ipv6 for action flag %u", parse_flag);
                    #endif
                    return TC_FORWARD;
                }
                else if (result.drop) {
                    #if DEBUG
                        bpf_printk("Mirror the packet, dropped by kernel for event monitoring from userSpace ");
                    #endif
                    // ipv6 addr dont need layer 3 checksum recalculation via checksum replace processing 
                    __handle_kernel_map_redirection_drop_count();
                    if (!config) {
                        __mark_skb_packet_buffer(skb, redirect_skb_mark);
                    }else {
                        __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                    }
                    
                    ipv6->daddr = bridge_redirect_addr_ipv6_malicious;
                    return bpf_redirect(br_index, BPF_F_INGRESS);
                }

                #if DEBUG
                    bpf_printk("A DNS packet was found over IPv6 and using UDP as the transport");
                #endif 
                // perform dpi here and mirror the packet using bpf_redirect over veth kernel bridge for veth interface 
                __u16 transaction_id = (__u16) bpf_ntohs(dns->transaction_id);
                __u16 sport = bpf_ntohs(udp->source);

                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
                    if (__update_checksum_dns_redirect_map_ipv6(transaction_id, sport) < 0) {
                        #if DEBUG 
                                bpf_printk("Error updating the kernel redirect map, the packet is dropped since kernel cannot monitor the \
                                                packet redirect lifecycle");
                        #endif 
                        return TC_DROP;
                    }
                    // Key not found, insert new element for the dns query id mapped to layer 3 checksum
                    // bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum_ipv6, BPF_ANY);
                } else {
                    if (__update_kernel_time_post_redirect(transaction_id, map_layer3_redirect_value) == TC_FORWARD) return TC_FORWARD;
                    return TC_FORWARD;
                }

                __handle_kernel_map_redirection_count();

                if (!config) {
                    __mark_skb_packet_buffer(skb, redirect_skb_mark);
                }else {
                    __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                }
                
                ipv6->daddr = bridge_redirect_addr_ipv6_suspicious;

                __update_kernel_packet_redirection_time(transaction_id);
                // forward the traffic to the brodhe fpr enhanced DPI in userspace 
                return bpf_redirect(br_index, BPF_F_INGRESS);
            }
            else {
                if (__parse_skb_non_standard(cursor, skb, actions, udp_payload_exclude_header, udp_data, udp_payload_len, udp, false) == 1)
                    return TC_FORWARD;
                return TC_DROP;
            }
            return TC_FORWARD;
        }else if (ipv6->nexthdr == IPPROTO_TCP) {

            if (actions.parse_tcp(&cursor, false) == 0) return TC_DROP;
            tcp = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if ((void *) tcp + 1 > cursor.data_end) return TC_DROP;
            void * tcp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            if ((void *) tcp_data + 1 > cursor.data_end) return TC_DROP;
            
            #if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
                EXFIL_SECURITY_FILTER_L3_NETPOOL_IPV6(ipv6);
            #endif

            if (tcp->dest == bpf_htons(DNS_EGRESS_PORT)
                || tcp->dest == bpf_htons(DNS_EGRESS_MULTICAST_PORT) 
                || tcp->dest == bpf_htons(LLMNR_EGRESS_LOCAL_MULTICAST_PORT)
            ){

                struct dns_header_tcp *dns = (struct dns_header_tcp *) tcp_data; 
                if ((void *) dns + 1 > cursor.data_end) return TC_DROP;

                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr)
                            + sizeof(struct dns_header_tcp); 
                
                if (actions.parse_dns_payload_transport_tcp(&cursor, dns_payload, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                // reached app layer no offset processing required from kernel 
                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload_transport_tcp(&cursor, dns_payload, dns);
    
                struct result_parse_dns_labels result = __parse_dns_flags_actions(parse_flag);

                __u32 skb_ifIndex = skb->ifindex;

                
                __u32 out = skb->ifindex;

                struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
                __u32 br_index = 4;  // loa  the redirection from the kernel 

                if (config) {
                    br_index = config->BridgeIndexId;
                }else {
                    bpf_printk("kernel cannot find the requred kernel config redirect map");
                }

                if (result.isBenign) 
                    return TC_FORWARD;
                else if (result.drop) {

                    __handle_kernel_map_redirection_drop_count();
                    
                    if (!config) {
                        __mark_skb_packet_buffer(skb, redirect_skb_mark);
                    }else {
                        __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                    }
    
                    
                    ipv6->daddr = bridge_redirect_addr_ipv6_malicious;
                    return bpf_redirect(br_index, BPF_F_INGRESS);
                }
                
                __u16 transaction_id = bpf_ntohs(dns->transaction_id);
                __u16 sport = bpf_ntohs(tcp->source);

                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
                    if (__update_checksum_dns_redirect_map_ipv6(transaction_id, sport) < 0) {
                        #if !DEBUG 
                            bpf_printk("Error updating the kernel redirect map, the packet is dropped since kernel cannot monitor the \
                                                packet redirect lifecycle");
                        #endif 
                        return TC_DROP;
                    }
                    // Key not found, insert new element for the dns query id mapped to layer 3 checksum
                    // bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum_ipv6, BPF_ANY);
                } else {
                    if (__update_kernel_time_post_redirect(transaction_id, map_layer3_redirect_value) == TC_FORWARD) return TC_FORWARD;
                    return TC_FORWARD;
                }

                __handle_kernel_map_redirection_count();
                if (!config) {
                    __mark_skb_packet_buffer(skb, redirect_skb_mark);
                }else {
                    __mark_skb_packet_buffer(skb,  config->KernelTCSKBMark);
                }

                __u32 tcp_payload_len = bpf_ntohs(ipv6->payload_len) - (tcp->doff * 4);
                if (result.deep_scan_mirror) {
                    #if DNS_RATE_LIMIT_VOLUME
                        __u8 dns_rate_limit_action = __dns_rate_limit(&cursor, skb, (__u32) tcp_payload_len);
                        if (dns_rate_limit_action == 0) return TC_DROP;
                    #endif

                    #if DNS_RATE_LIMIT_TOCKEN_BUCKET
                        if (__dns_rate_limit_tb(&cursor, skb) == 0) {
                            if (DEBUG) bpf_printk("Dropping DNS egress suspicious traffic exceed thrshold for Tocken Bucket rate limit");
                            return TC_DROP;
                        }
                    #endif 
                }

                ipv6->daddr = bridge_redirect_addr_ipv6_suspicious;
               
                // forward the traffic to the brodhe fpr enhanced DPI in userspace 
                __update_kernel_packet_redirection_time(dns->transaction_id);
                return bpf_redirect(br_index, BPF_F_INGRESS);
            }
            else {
                if (__parse_skb_non_standard_tcp(cursor, skb, actions, tcp_data, false) == 1) 
                    return TC_FORWARD;
                
                return TC_FORWARD;
            }
            
        }
    } else return TC_FORWARD; // likely a kernel vxland packet over the virtual bridge 

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
