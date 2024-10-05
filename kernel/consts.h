


#ifndef DNS_EGRESS_PORT
    #define DNS_EGRESS_PORT 53 
#endif


// a all main custom flag for parsing the packet after redirection from N/S to a different port on same net-device 
#ifndef RESERVED_KERNEL_SKBUFF_MAP 
    #define RESERVED_KERNEL_SKBUFF_MAP 1 
#endif

#define ull unsigned long long 
#define uc unsigned char 
#define ll long 

struct exfil_map_domain_config {
    __u32 br_index_id;
    __u32 br_gateway_subnet; 
    __u32 br_egress_redirect_ns_ip;
    __u32 br_egress_forward_ns_ip;
};

struct exfil_security_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct exfil_map_domain_config);
    __uint(max_entries, 1 << 6);
} exfil_security_config_map SEC(".maps");



#define MAX_DNS_QDCOUNT 3 
#define MAX_DNS_ANS_COUNT 3
#define MAX_DNS_AUTH_COUNT 3 
#define MAX_DNS_ADD_COUNT 3 
#define MAX_PACKET_OFF 0xffff



#define MAX_DNS_NAME_LENGTH 255 
#define MAX_DNS_LABEL_LENGTH 63 
#define MAX_DNS_LABEL_COUNT 127


__u32 redirect_skb_mark = 1;


// 10.200.0.1
#ifndef BRIDGE_REDIRECT_ADDRESS_IPV4
    #define BRIDGE_REDIRECT_ADDRESS_IPV4 0x0AC80001 
#endif


// fe80::5c0a:20ff:fe93:9ef1
#ifndef BRIDGE_REDIRECT_ADDRESS_IPV6
    #define BRIDGE_REDIRECT_ADDRESS_IPV6 0xfe800000000000005c0a20fffe939ef1
#endif