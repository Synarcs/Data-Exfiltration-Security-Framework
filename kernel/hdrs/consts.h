/* 
    Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

#ifndef __CONST_H_ 
#define __CONST_H_ 

// disable local stack warnings for always inline fucns 
#pragma clang diagnostic ignored "-Wreturn-stack-address"
#pragma clang diagnostic ignored "-Wbackslash-newline-escape"
#pragma clang diagnostic ignored "-Wunused-parameter"

#include <linux/ipv6.h>
#include <linux/in6.h>
#include <stdbool.h>

// kernel actions for tc susbsytem for all traffic control action forward 
#ifndef tc 
    #define TC_FORWARD TC_ACT_OK
    #define TC_DEFAULT TC_ACT_UNSPEC
    #define TC_DROP TC_ACT_SHOT
#endif

#ifndef NETDEV_LINK_LB_STUB_RESOLVER
    #define NETDEV_LINK_LB_STUB_RESOLVER false
#endif


#define DPI_KERNEL_PERF_BENCH true 
#define DPI_KERNEL_PERF_BENCH_SCAN_INTERVAL 1 << 12 

// a all main custom flag for parsing the packet after redirection from N/S to a different port on same net-device 
#ifndef RESERVED_KERNEL_SKBUFF_MAP 
    #define RESERVED_KERNEL_SKBUFF_MAP 1 
#endif

#ifndef KERNEL_DPI_PACKET_DP_EXPORTERS
    #define KERNEL_DPI_PACKET_DP_EXPORTERS true
#endif 

#define ull unsigned long long 
#define uc unsigned char 
#define ll long 

/* 
    Each key maps to the service limits for the dns traffic, for example 
    0 --> min_domain_lenth, 1 --> max_domain_length and so on
*/
struct exfil_security_egress_dns_limites {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1 << 4);
} exfil_security_egress_dns_limites SEC(".maps");


#define MAX_DNS_QDCOUNT 3 
#define MAX_DNS_ANS_COUNT 3
#define MAX_DNS_AUTH_COUNT 3 
#define MAX_DNS_ADD_COUNT 3 
#define MAX_PACKET_OFF 0xffff

#define MAX_DNS_NAME_LENGTH 255 
#define MAX_DNS_LABEL_LENGTH 63 
#define MAX_DNS_LABEL_COUNT 127

// Pull all this from eBPF map config for dynamic packet filtering in kernel 

// deep scan kernel packets for overlay l4 protocols 
#define DEEP_SCAN_DNS_UDP_OVERLAY true
#define DEEP_SCAN_DNS_TCP_OVERLAY true

#define DROP_L3_DYANMIC_NETPOOL_TRAFFIC false

// if enabled the eBPF node agent in user-space dynamically inject L3, inet in kernel over TC for eBPF in kernel tc to stop any DNS traffic with these l3 traffic 
// For cloud the eBPF node agent dynamicaaly create netpools for l3 netpools, (eBPF sock / iptables / ipvs) for the CNI in k8s to block DNS upstream traffic to any of such Ip in the network 
#define L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS true
#define L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS false 

// enhanced other feature tracking in kernel fro cross protocol breach coorelation and trackign, once prevented over DNS 
#define EXFIL_SEC_CROSS_PROTOCOL_RELATION false 


// rate limit config
#define DNS_RATE_LIMIT_VOLUME false
#define DNS_RATE_LIMIT_TOCKEN_BUCKET false


// skb netflow handling 
#define SKB_B32_KERNEL_RAND_PER_NETFLOW true 

#define IPV6_ROUTE 1 

#ifndef TC_TASK_COMM_EGRESS_CLSACT_SUPPORT 
    #define TC_TASK_LINUX_MAJOR_RELEASE_SUPPORT 6 
    #define TC_TASK_LINUX_SUBRELEASE_SUPPORT 10 
    #define TCX_LINUX_MAJOR_RELEASE_SUPPORT 6 
    #define TCX_LINUX_SUBRELEASE_SUPPORT 6 
#endif

// envoy filter sock options over kernel sock layer to prevent skb peer redirection loop over sockets
// the kernel egress tc does not consider filter wasm envoy processing 
#define ENVOY_DPI_TCP_PORT 9801
#define CONTROLLER_RPC_SVC_PORT 3200
#define EDR_PPROF_PORT 6262
#define ENVOY_DPI_WASM_TCP_FILTER true

#define DETECTED_MALICIOUS_COUNT_DNS_RANDOM_PORT_DROP_LIMIT 1

// defines the mal threshold kill proc , integration with the kernel syscall layer
#define EGRESS_MAL_PROC_EXFIL_SCHED 3 
#define EGRESS_DETECTED_MAP_PROC_MAX_FORK_CT 3 

#define REDIRECT_SKB_MARK 0xFFFF


// use the kernel eBPF maps to inject the dynamic config to process all the l3 filters 
// TODO: All the kernel addon DPI filter must be injected in runtime from endpoint security agent in userspace inside kernel for security
static 
__always_inline void __configure_l3_filter_options() {
}

// 10.200.0.1 this is only for testing in kernel while parsing the process 
#ifndef BRIDGE_REDIRECT_ADDRESS_IPV4
    #define BRIDGE_REDIRECT_ADDRESS_IPV4 0x0AC80001 
    #define BRIDGE_REDIRECT_ADDRESS_IPV4_TUNNEL 0x0AD20002
    #define BRIDGE_REDIRECT_ADDRESS_IPV4_MALICIOUS 0x0AC80002 
#endif

#ifdef IPV6_ROUTE 
    // TODO: Let user space dynamically inject the ipv6 8 * 16 byte address in kernel for route rewrite 
    // fe80::d091:3cff:fe25:6d96/64
    struct in6_addr bridge_redirect_addr_ipv6_suspicious = {
        .in6_u.u6_addr16 = {
           bpf_ntohs(0xfe80), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0xd091), 
           bpf_ntohs(0x3cff), 
           bpf_ntohs(0xfe25), 
           bpf_ntohs(0x6d96), 
        }
    };

    // fe80::d091:3cff:fe25:6d97/64
    struct in6_addr bridge_redirect_addr_ipv6_malicious = {
        .in6_u.u6_addr16 = {
           bpf_ntohs(0xfe80), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0xd091), 
           bpf_ntohs(0x3cff), 
           bpf_ntohs(0xfe25), 
           bpf_ntohs(0x6d97), 
        }
    };

    // // fe80::d091:3cff:fe25:6d98/64 (ipv6 route for malicious) 
    struct in6_addr bridge_redirect_addr_ipv6_malicious_tunnel = {
        .in6_u.u6_addr16 = {
           bpf_ntohs(0xfe80), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0x0000), 
           bpf_ntohs(0xd091), 
           bpf_ntohs(0x3cff), 
           bpf_ntohs(0xfe25), 
           bpf_ntohs(0x6d98), 
        }
    };
#endif
// fe80::5c0a:20ff:fe93:9ef1

typedef struct inet6_bridge_address {
    struct in6_addr inet_addr[2];
} __attribute__((packed)) inet6_bridge_address;


#ifdef IPV6_ROUTE 
    // should be configured in runtime over discrete IPAM at the endpoint 
    inet6_bridge_address * configure_global_ipv6_route_handlers() {
        inet6_bridge_address inet_addr_map = {};
        inet_addr_map.inet_addr[0] = (struct in6_addr){
            .in6_u.u6_addr16 = {
            bpf_ntohs(0x2001), 
            bpf_ntohs(0x4860), 
            bpf_ntohs(0x4860), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x8888), 
            }
        };
        inet_addr_map.inet_addr[1] = (struct in6_addr){
            .in6_u.u6_addr16 = {
            bpf_ntohs(0x2001), 
            bpf_ntohs(0x4860), 
            bpf_ntohs(0x4860), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x0000), 
            bpf_ntohs(0x8844), 
            }
        };
        return &inet_addr_map;
    }
#endif

struct result_parse_dns_labels {
    bool deep_scan_mirror;
    bool drop;
    bool isBenign;
    bool isC2c;
} __attribute__((packed));

// ipv6 has no checksum but kept this for kernel map verification 
#define DEFAULT_IPV6_CHECKSUM_MAP 0xff


#ifndef WIN_PHYSICAL_HYPERVISOR
    #define WIN_PHYSICAL_HYPERVISOR 0 
#endif 

// default kernel Birdge If_indexes , kernel internally does DNAT, SNAT
#define RE_SCAN_BRIDGE_IF_INDEX_DEFAULT_CLONE_FORWARD_REDIRECT 5
#define RE_SCAN_BRIDGE_IF_INDEX_DEFAULT_FORWARD_REDIRECT 4


#ifndef MAX_PROC_COMM_SIZE
    #define MAX_PROC_COMM_SIZE 200 
#endif 



#endif /* __EXFIL_SECURITY_H */
