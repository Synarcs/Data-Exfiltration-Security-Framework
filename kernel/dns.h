#include <linux/in.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/icmp.h>

//bpf map parameters
#define MAX_SIZE 1024;
#define MAX_ENTRIES 1024;

#define DEBUG false 

enum MALICIOUS_FLAGS {
        BENIGN = 0,
        SUSPICIOUS,
        MALICIOUS
} flags;


struct dns_header {
    __u16 transaction_id;
    __u8 rd: 1;      //Recursion desired
    __u8 tc: 1;      //Truncated
    __u8 aa: 1;      //Authoritive answer
    __u8 opcode: 4;  //Opcode
    __u8 qr: 1;      //Query/response flag
    __u8 rcode: 4;   //Response code
    __u8 cd: 1;      //Checking disabled
    __u8 ad: 1;      //Authenticated data
    __u8 z: 1;       //Z reserved bit
    __u8 ra: 1;      //Recursion available
    __be16 qd_count;    //Number of questions
    __be16 ans_count;  //Number of answer RRs
    __be16 auth_count; //Number of authority RRs
    __be16 add_count;  //Number of resource RRs
} __attribute__((packed));

struct dns_query_section {
    __u16 record_type;
    __u16 classId;
    char domain_name[256];
} __attribute__((packed));

struct dns_answer_section {
    __u16 query_pointer;
    __u16 record_type;
    __u16 classId;
    __u32 ttl;
    __u16 data_length;
} __attribute__((packed));

struct a_record {
    struct in_addr ip_addr;
    __u32 ttl;
};


struct dns_record_limits {
    int MAX_DOMAIN_LENGTH;
    int MAX_SUBDOMAIN_LENGTH;
    int MAX_SUBDOMAIN_NESTING;
    int MALICIOUS_DOMAIN_QUERY_LENGTH;
} DNS_RECORD_LIMITS = {
        255, 63,
        127,
        55
};


struct dns_event {
    __u32 eventId;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 payload_size;
    __u32 udp_frame_size;
    __u32 dns_payload_size; // size of payload excluding the dns header 
    __u8 isUDP; // offset udp calc 
    __u8 isIpv4; // ipv4 processing 
};




struct exfil_security_dropped_payload_event {
    union {
        __u32 src_ip;  // src 
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u8 protocol;
    };
    union {
        __be16 qd_count;    //Number of questions
        __be16 ans_count;  //Number of answer RRs
        __be16 auth_count; //Number of authority RRs
        __be16 add_count;  //Number of resource RRs
    };
};
