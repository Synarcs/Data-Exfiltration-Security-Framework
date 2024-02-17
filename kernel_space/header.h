#include <linux/bpf.h>
#include <arpa/inet.h>
#include <stdbool.h>

struct __domain_event {
    char domain[255];
    char classification[1];
};

#ifndef DNS_PORT
    #define DNS_PORT = 53
#endif


#define MAX_SIZE 1024;
#define MAX_ENTRIES 1024;
#define MAX_DNS_SUBDOMAIN_LENGTH 55;
#define MAX_DNS_DOMAIN_LENGTH 255;
#define DEBUG true

 enum MALICIOUS_FLAGS {
        BENIGN = 0,
        MALICIOUS,
        SUSPICIOUS
};

 struct dns_header {
    __be16 id;
    uint8_t rd: 1;      //Recursion desired
    uint8_t tc: 1;      //Truncated
    uint8_t aa: 1;      //Authoritive answer
    uint8_t opcode: 4;  //Opcode
    uint8_t qr: 1;      //Query/response flag
    uint8_t rcode: 4;   //Response code
    uint8_t cd: 1;      //Checking disabled
    uint8_t ad: 1;      //Authenticated data
    uint8_t z: 1;       //Z reserved bit
    uint8_t ra: 1;      //Recursion available
    __be16 qd_count;    //Number of questions
    __be16 ans_count;  //Number of answer RRs
    __be16 auth_count; //Number of authority RRs
    __be16 add_count;  //Number of resource RRs
};

 struct dns_answer_section {
    uint16_t query_pointer;
    uint16_t record_type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_length;
} __attribute__((packed));

 struct dns_query_section {
    uint16_t record_type;
    uint16_t class;
    char domain_name[(1 << 8) - 1];
};

 struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};

