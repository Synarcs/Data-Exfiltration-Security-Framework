


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



