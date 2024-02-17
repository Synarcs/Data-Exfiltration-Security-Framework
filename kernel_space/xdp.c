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
#include <sys/mman.h>

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

    int namepos = 0;
    uint16_t i = 0; // max value is 1 << 8 - 1

    memset(&q->domain_name[0], 0, sizeof(q->domain_name));
    memset(&q->record_type, 0, sizeof(uint16_t));
    memset(&q->class, 0, sizeof (uint32_t));

    q->record_type = 0;
    q->class = 0;

    const int max = 255;
    // 16 bit is enough to count the subdomains
    uint16_t *subdomain_count; *(subdomain_count) = 0;
    int label_count = 0; int domain_length = 0;

    for (i = 0; i < (int) max  ; i++) {
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
        int val = (int) q->domain_name[namepos];

        if (val <= 20) {
            q->domain_name[namepos] = (char) '.';
            if (__verify_sub_domain_length(&label_count)){
#ifdef DEBUG
                bpf_printk("Error the length of the subdomain exceed limit is malicious");
#endif
                return DROP;
            }
            label_count = 0;
        }else {
            label_count++;
        }

        domain_length++;

        if (__verify_dns_domain_sperator(&q->domain_name[namepos])) {
            *subdomain_count = *(subdomain_count)+1;
        }
        namepos++;
        cursor++;
    }

    *(subdomain_count) = *(subdomain_count) - 1; // remove the delimeter in the domain count

#ifdef DEBUG
    bpf_printk("The process label count is %d and domain length %d: and subdomains :: %d", label_count, domain_length,
                            *subdomain_count);
#endif

    if (label_count > 0 && __verify_sub_domain_length(&label_count))
        return DROP;

    if (*subdomain_count > DNS_RECORD_LIMITS.MALICIOUS_DOMAIN_QUERY_LENGTH)
        return MALICIOUS;



    if (*subdomain_count < 1){
        // a invalid packet because it does not follow the dns rfc
        return DROP;
    }else if (*subdomain_count  == 1) { // a tld allow it it is a valid dmain
        return BENIGN;
    }else {  // since it has more domain length or also an mal formed packet let the user space process and handle it
        return SUSPICIOUS;
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
__always_inline enum XDP_DECISION __parse_dns_spoof(struct udphdr *udp_hdr, struct xdp_md *skb, struct iphdr *ip){
    uint16_t dest = bpf_ntohs(udp_hdr->dest);

    bpf_printk("A UDP Packet was found and loaded Possibly DNS %u", dest);

    if (dest == 53) {
        void * dns_head = (void *) udp_hdr + sizeof (udp_hdr);

        struct dns_header *dnsHeader = dns_head;
        if ((void *) dnsHeader + sizeof (struct dns_header) > (void *) skb->data_end){
#ifdef DEBUG
            bpf_printk("The header length for the payload exceed the max range");
#endif
            return DENY;
        }
        else {
            void *extra_dns_data_section = (void *) dnsHeader + sizeof (struct dns_header);
            if ((void *) extra_dns_data_section + sizeof (struct dns_header) > (void *) skb->data_end){
                return DENY;
            }
            struct dns_query_section querySection;

            if (dnsHeader->qd_count == 1 && dnsHeader->ans_count == 0){
                // possibly the malware is trying to do exfiltration to get attacker's ip address a ipv4 or ipv6 from A type domain
                // to the attacker's namesapce
                switch (__parse_dns_query_sections(skb,  extra_dns_data_section, &querySection)) {
                    case DROP:
                    case MALICIOUS: {
                        return DENY;
                    }
                    case BENIGN: {
                        return ALLOW;
                    }
                    case SUSPICIOUS: {
                        // add the z header padding for the user space to define the faith
                        dnsHeader->z = (uint8_t) 1;
                        return ALLOW;
                    }
                }
                // only possible is to check for the domain names and lalbels in the domain
                /**
                 * TODO
                 *      check for the labels
                 *      check for the domains names
                 *      check for subdomain length count
                 *      check for subdomain count
                 *      check for entropy if the instruction cycle for the space remains inside limit
                 *
                 *      emit the suspicious to user space for stateless packet evaluation using deep learning
                 */
                bpf_printk("%u %u", ntohs(dnsHeader->qd_count), ntohs(dnsHeader->ans_count));
            }else if (dnsHeader->qd_count >= 1
                      && dnsHeader ->ans_count >= 1){
                __parse_dns_query_sections(skb,  extra_dns_data_section, &querySection);
                __parse_dns_answer_sections(skb,  extra_dns_data_section, &querySection);
                /*
                 * Check both the query as well as the answer section for the dns-header
                 */

            }
        }
        return true;
    }
    return false;
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
                                if (__parse_dns_spoof(udp, ctx, ip)) {
                                    return XDP_DROP;
                                }
                                return XDP_PASS;
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
                    if ((void *) tcp_header + sizeof (struct  tcphdr) < data_end){}
                    uint64_t ddport = ntohs(tcp_header->dest);
                    return XDP_PASS;
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