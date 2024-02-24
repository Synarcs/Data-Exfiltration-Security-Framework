#pragma once

#include <linux/in.h>
#include <linux/in.h>
#include <linux/types.h>

struct __domain_event {
    char domain[255];
    char classification[1];
};

struct __xdp_payload {
    void *data;
    void *data_end;
};

#ifndef DNS_PORT
    #define DNS_PORT = 53
#endif

//bpf map parameters
#define MAX_SIZE 1024;
#define MAX_ENTRIES 1024;

#define DEBUG true
#define DNS_DEBUG false


enum MALICIOUS_FLAGS {
        BENIGN = 0,
        MALICIOUS,
        SUSPICIOUS,
        DROP
};

enum XDP_DECISION {
    ALLOW = 0,
    DENY,
};


 struct dns_header {
    __be16 id;
    u8 rd: 1;      //Recursion desired
    u8 tc: 1;      //Truncated
    u8 aa: 1;      //Authoritive answer
    u8 opcode: 4;  //Opcode
    u8 qr: 1;      //Query/response flag
    u8 rcode: 4;   //Response code
    u8 cd: 1;      //Checking disabled
    u8 ad: 1;      //Authenticated data
    u8 z: 1;       //Z reserved bit
    u8 ra: 1;      //Recursion available
    __be16 qd_count;    //Number of questions
    __be16 ans_count;  //Number of answer RRs
    __be16 auth_count; //Number of authority RRs
    __be16 add_count;  //Number of resource RRs

} __attribute__((packed));

struct dns_query_section {
    u16 record_type;
    u16 class;
    char domain_name[256];
} __attribute__((packed));

struct dns_answer_section {
    u16 query_pointer;
    u16 record_type;
    u16 class;
    u32 ttl;
    u16 data_length;
} __attribute__((packed));

struct a_record {
    struct in_addr ip_addr;
    u32 ttl;
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

