#include <linux/ipv6.h>
#include <linux/in6.h>
#include <stdbool.h>


#ifndef DNS_EGRESS_PORT
    #define DNS_EGRESS_PORT 53 
    #define DOT_EGRESS_PORT 853
    #define DNS_EGRESS_MULTICAST_PORT 5353
#endif


// a all main custom flag for parsing the packet after redirection from N/S to a different port on same net-device 
#ifndef RESERVED_KERNEL_SKBUFF_MAP 
    #define RESERVED_KERNEL_SKBUFF_MAP 1 
#endif

#define ull unsigned long long 
#define uc unsigned char 
#define ll long 

struct exfil_kernel_config  {
    __u32 BridgeIndexId;
    __be32 RedirectIpv4;
};

struct exfil_security_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct exfil_kernel_config);
    __uint(max_entries, 1 << 6);
} exfil_security_config_map SEC(".maps");


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

#define IPV6_ROUTE 1 

__u32 redirect_skb_mark = 0xFF;


// 10.200.0.1 this is only for testing in kernel while parsing the process 
#ifndef BRIDGE_REDIRECT_ADDRESS_IPV4
    #define BRIDGE_REDIRECT_ADDRESS_IPV4 0x0AC80001 
    #define BRIDGE_REDIRECT_ADDRESS_IPV4_MALICIOUS 0x0AC80002 
#endif

#ifdef IPV6_ROUTE 
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
#endif
// fe80::5c0a:20ff:fe93:9ef1

struct result_parse_dns_labels {
    bool deep_scan_mirror;
    bool drop;
    bool isBenign;
} __attribute__((packed));



// RATE LIMITER 
#define TIMEWINDOW 10000000000
#define MAX_VOLUME_THRESHOLD 600000 

#define MAX_FREQUENCY_PER_SEC 100
