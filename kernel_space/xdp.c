// libbpf
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//  cutils
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>

// linux net stack
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "header.h"
#include "maps.h"
#include "init.h"

/**
 *  Need to use the tail Stack recursion to save some space for the stack in the kernel
 *   Return and use bpf_tail_call for n order tail func call in the bpf stack space.
 */

/**
 *   All the static rule checks that the xdp process handles for processing
 */
static
__always_inline bool __verify_dns_domain_sperator(char *buffer){
    return *(buffer) == '.' ? true : false;
}

static
__always_inline bool __verify_sub_domain_length(int *label_count){
    return *(label_count) > DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH ? true : false;
}

static
__always_inline bool __verify_suspicious_subdomain_length(int *label_count){
    return *(label_count) > DNS_RECORD_LIMITS.MALICIOUS_DOMAIN_QUERY_LENGTH;
}

static
__always_inline bool __verify_dns_labels(char *buffer) {return false;}

static __always_inline bool __parse_ip_header(struct iphdr *ip, struct xdp_md *mem){
    return true;
}

/**
 *
 * @param skb  the xdp socket buffer
 * @param extra_dns_data_section
 * @param q
 * @return -1 : Harmful and Malicious
 *          0:  Kernel Space cannot determine let the user space define
 *          1: Benigh
 */
static
__always_inline enum MALICIOUS_FLAGS __parse_dns_query_sections(struct xdp_md *skb, void *extra_dns_data_section,
                                                                struct dns_query_section *q) {
    void *mem_end = (void *) (long) skb->data_end;
    void *cursor = extra_dns_data_section;

    int namepos = 0; uint16_t i = 0; // max value is 1 << 8 - 1
    // 16 bit is enough to count the subdomains
    uint16_t subdomain_count = 0;
    int label_count = 0; int domain_length = 0;


    memset(&q->domain_name[0], 0, sizeof(q->domain_name));
    memset(&q->record_type, 0, sizeof(uint16_t));
    memset(&q->class, 0, sizeof (uint32_t));


    for (i = 0; i < (int) 255  ; i++) {
        if (cursor + 1 > mem_end) {
#ifdef  DEBUG
            bpf_printk("Error the Reading out for a unsafe mem location");
#endif
            break;
        }
        // check for the null length termination at the end, reached the string end
        if (*(char *) cursor == 0) {
            if (cursor + 5 > mem_end) {
#ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
#endif
            } else {
                q->record_type = bpf_htons(*(uint16_t *) (cursor + 1));
                q->class = bpf_htons(*(uint16_t *) (cursor + 3));
            }
            namepos = namepos * 2 * 2 + 1;
            break;
        }

        q->domain_name[namepos] = *(char *) cursor;

        if ( (int) q->domain_name[namepos] <= 20) {
            q->domain_name[namepos] = (char) '.';

//
//            if (label_count > DNS_RECORD_LIMITS.MALICIOUS_DOMAIN_QUERY_LENGTH) return SUSPICIOUS;
//            subdomain_count++;
//            label_count = 0;
        }else {
            label_count++;
        }

//#ifdef DNS_DEBUG
        bpf_printk("the payload is %c %d %d", q->domain_name[namepos], label_count, subdomain_count);
//#endif

        domain_length++;
        namepos++;
        cursor++;
    }

    subdomain_count--;
    domain_length--;

#ifdef DNS_DEBUG
    bpf_printk("the first char is : %c", q->domain_name[0]);
#endif

#ifdef DNS_DEBUG
    bpf_printk("The process label count is %d and domain length %d: and subdomains", domain_length,
               subdomain_count);
#endif

    if (label_count > 0 && __verify_sub_domain_length(&label_count)) // verify the last remaining tld
        return DROP;

    if ( subdomain_count < 1){
        // a invalid packet because it does not follow the dns rfc
        return DROP;
    }else if (subdomain_count == 1) { // a tld allow it it is a valid dmain
        return BENIGN;
    }else {  // since it has more domain length or also an mal formed packet let the user space process and handle it
        return SUSPICIOUS; // let user space handle it
    }
}

static
__always_inline enum MALICIOUS_FLAGS __parse_dns_answer_sections(struct xdp_md *skb, void *extra_dns_data_section,
                                                                 struct dns_query_section *q){
    return -1;
}

static
__always_inline enum MALICIOUS_FLAGS __parse_dns_addon_sections(struct xdp_md *skb, void *extra_dns_data_section, struct dns_query_section *q){
    return -1;
}


// pass the latest order buffer for top 2 layers of the protocol
static
__always_inline enum XDP_DECISION __parse_dns_spoof(struct udphdr *udp_hdr, struct xdp_md *skb, struct iphdr *ip,
                    struct tcphdr *tcp_hdr){
    uint16_t dest = bpf_ntohs(udp_hdr->dest);

    if (dest == 53) {
        void * dns_head = (void *) udp_hdr + sizeof (*udp_hdr);
        bpf_printk("A UDP Packet was found and loaded Possibly DNS %u", dest);
        struct dns_header *dnsHeader = dns_head;
        if ((void *) dnsHeader + sizeof (*dnsHeader) > (void *) skb->data_end){
#ifdef DEBUG
            bpf_printk("The header length for the payload exceed the max range");
#endif
            return DENY;
        }
        else {
            if ((void *) dnsHeader + sizeof (*dnsHeader) > (void *) skb->data_end){
                bpf_printk("fuck found bad");
                return DENY;
            }
            void *extra_dns_data_section = (void *) dnsHeader + sizeof (*dnsHeader);

#ifdef DNS_DEBUG
            bpf_printk("A DNS Packet was found with some extra : %u :: %u", dnsHeader->qr , dnsHeader->opcode);
            bpf_printk("A DNS Packet was found with some extra : %u :: %u",             bpf_ntohs(dnsHeader->qd_count)
            ,            bpf_ntohs(dnsHeader->ans_count)
            );
#endif

            if (dnsHeader->opcode == 1) return DENY;

            switch (dnsHeader->qr) {
                case 0:{
                    uint16_t queryCount = bpf_ntohs(dnsHeader->qd_count);
                    struct dns_query_section querySection;

                    switch ( __parse_dns_query_sections(skb, extra_dns_data_section, &querySection)) {
                        case MALICIOUS:
                        case DROP:
                            return DENY;
                        case BENIGN:
                            return ALLOW;
                        case SUSPICIOUS:{
                            dnsHeader->z = 1; // set the 1 flag as let user space make decious
                            return ALLOW;
                        }
                    }

                }
                case 1:{
                    uint16_t queryCount = bpf_ntohs(dnsHeader->qd_count);
                    uint16_t responseCount = bpf_ntohs(dnsHeader->ans_count);
                    struct dns_answer_section answerSection;
                    struct dns_query_section querySection;

                    __parse_dns_query_sections(skb, extra_dns_data_section, &querySection);
                }
                default: return DENY;
            }
        }
    }
    return ALLOW;
}

SEC("xdp")
int handler(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *ingress = (void *) (long ) ctx->ingress_ifindex;

    struct ethhdr *eth = data;

    if ((void *)eth + sizeof (*eth) > data_end) return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_8021AD) || eth -> h_proto == bpf_htons(ETH_P_8021AD)){}


    if ((void *)eth + sizeof(*eth) <= data_end) {

        struct iphdr *ip = data + sizeof (*eth);

        if ((void *)ip + sizeof(*ip) <= data_end) {
            switch (ip->protocol) {

                case IPPROTO_UDP:
                {
                    struct udphdr *udp = (void *)ip + sizeof(*ip);
                    uint64_t dport = bpf_ntohs(udp->dest);
                    if ((void *)udp + sizeof(*udp) <= data_end) {
                        switch (bpf_htons(udp->dest)) {
                            case 53: {
                                switch (__parse_dns_spoof(udp, ctx, ip, NULL)) {
                                    case ALLOW: return XDP_PASS;
                                    case DENY: return XDP_DROP;
                                }
                            }
                            default:{
                                return XDP_PASS;
                            }
                        }
                    } else {
#ifdef DEBUG
                        bpf_printk("Error in reading restricted memory");
#endif
                        return XDP_DROP;
                    }
                }
                case IPPROTO_TCP: {
                      struct tcphdr *tcp_header = (void *)ip + sizeof (struct iphdr);
                    if ((void *) tcp_header + sizeof (*tcp_header) >= data_end){
                        return XDP_DROP;
                    } else {
                        uint64_t dport = bpf_htons(tcp_header->dest);
                        uint64_t sport = bpf_htons(tcp_header->source);

                        return XDP_PASS;
                    }
                }
                default: {
                    return XDP_PASS;
                }
            }
        }
    }

    return XDP_PASS;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";