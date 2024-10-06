#include <linux/in.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/icmp.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

//bpf map parameters
#define MAX_SIZE 1024;
#define MAX_ENTRIES 1024;

#define DEBUG false 

enum MALICIOUS_FLAGS {
        BENIGN = 0,
        SUSPICIOUS,
        MALICIOUS
} flags;

//   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#define DNS_RCODE_MASK  0x000F 
#define DNS_CD_MASK     0x0010  
#define DNS_AD_MASK     0x0020  
#define DNS_Z_MASK      0x0040  
#define DNS_RA_MASK     0x0080  
#define DNS_RD_MASK     0x0100
#define DNS_TC_MASK     0x0200 
#define DNS_AA_MASK     0x0400  
#define DNS_OPCODE_MASK 0x7800 
#define DNS_QR_MASK     0x8000


#define DNS_RCODE_SHIFT  0   
#define DNS_CD_SHIFT     4
#define DNS_AD_SHIFT     5
#define DNS_Z_SHIFT      6
#define DNS_RA_SHIFT     7
#define DNS_RD_SHIFT     8
#define DNS_TC_SHIFT     9
#define DNS_AA_SHIFT    10   
#define DNS_OPCODE_SHIFT 11  
#define DNS_QR_SHIFT    15

struct dns_flags {
    __u8 qr;
    __u8 opcode;
    __u8 aa;
    __u8 tc;
    __u8 rd;
    __u8 ra;
    __u8 z;
    __u8 ad;
    __u8 cd;
    __u8 rcode;
};

struct qtypes {
    __u8 A; __u8 NS; __u8 CNAME;__u8 SOA;__u8 PTR;__u8 MX;__u8 TXT;__u8 AAAA;__u8 SRV;__u8 NAPTR;__u8 OPT;
    __u8 HTTPS;__u8 ANY;
} qtypes = {
    .A =  0x0001,
    .NS = 0x0002,
    .CNAME =  0x0005,
    .SOA = 0x0006,
    .PTR = 0x000C,
    .MX = 0x000F,
    .TXT = 0x0010,
    .AAAA = 0x001C,
    .SRV = 0x0021,
    .NAPTR = 0x0023,
    .OPT = 0x0029,
    .HTTPS = 0x0041,
    .ANY = 0x00FF,
};

struct dns_header {
    __u16 transaction_id;
    __u16 flags;
    __be16 qd_count;    //Number of questions
    __be16 ans_count;  //Number of answer RRs
    __be16 auth_count; //Number of authority RRs
    __be16 add_count;  //Number of resource RRs
} __attribute__((packed));

static 
__always_inline struct dns_flags  get_dns_flags (struct dns_header * dns_header) {
    struct dns_flags flags;
    __u16 host_order_flags = bpf_ntohs(dns_header->flags);
    flags = (struct dns_flags) {
        .qr = (host_order_flags & DNS_QR_MASK) >> DNS_QR_SHIFT,
        .opcode = (host_order_flags & DNS_OPCODE_MASK) >> DNS_OPCODE_SHIFT,
        .aa = (host_order_flags & DNS_AA_MASK) >> DNS_AA_SHIFT,
        .tc = (host_order_flags & DNS_TC_MASK) >> DNS_TC_SHIFT,
        .rd = (host_order_flags & DNS_RD_MASK) >> DNS_RD_SHIFT,
        .ra = (host_order_flags & DNS_RA_MASK) >> DNS_RA_SHIFT,
        .z = (host_order_flags & DNS_Z_MASK) >> DNS_Z_SHIFT,
        .ad = (host_order_flags & DNS_AD_MASK) >> DNS_AD_SHIFT,
        .cd = (host_order_flags & DNS_CD_MASK) >> DNS_CD_SHIFT,
        .rcode = (host_order_flags & DNS_RCODE_MASK) >> DNS_RCODE_SHIFT
    };
    return flags;
}

//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
struct dns_query_section {
    __u16 record_type;
    __u16 classId;
    __u16 qclass;
} __attribute__((packed));


 //   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 // |                                               |
 // /                                               /
 // /                      NAME                     /
 // |                                               |
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 // |                      TYPE                     |
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 // |                     CLASS                     |
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 // |                      TTL                      |
 // |                                               |
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 // |                   RDLENGTH                    |
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 // /                     RDATA                     /
 // /                                               /
 // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 
struct dns_answer_section {
    __u16 name;
    __u16 record_type;
    __u16 class;
    __u16 ttl;
    __u16 rdlength;
    __u16 rdata;
} __attribute__((packed));

struct a_record {
    struct in_addr ip_addr;
    __u32 ttl;
};

// define the malicious domain record limits 
struct dns_record_limits_malicious {
    int MIN_DOMAIN_LENGTH;
    int MAX_DOMAIN_LENGTH;

    // define the per label length range 
    int MIN_SUBDOMAIN_LENGTH_PER_LABEL;
    int MAX_SUBDOMAIN_LENGTH_PER_LABEL;

    // define the range for kernel to 
    int MIN_SUBDOMAIN_LABEL_COUNT;
    int MAX_SUBDOMAIN_LABEL_COUNT;
    
} __attribute__((packed)) DNS_RECORD_LIMITS = {
        130,
        255, 

        17,
        63,

        8,
        127
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
