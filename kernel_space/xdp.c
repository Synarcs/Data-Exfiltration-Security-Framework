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
__always_inline bool __verify_sub_domain_count(char *buffer){
    return *(buffer) == '.' ? true : false;
}

static
__always_inline bool __verify_sub_domain_length(char *buffer){ return true;}

static
__always_inline bool __verify_dns_labels(char *buffer) {return false;}

static __always_inline bool __parse_ip_header(struct iphdr *ip, struct xdp_md *mem){
    return true;
}

static
__always_inline int __parse_dns_query_sections(struct xdp_md *skb, void *extra_dns_data_section,
                struct dns_query_section *q){
    void *mem_end = (void *) (long) skb->data_end;
    void *cursor = extra_dns_data_section;


    int namepos = 0;
    uint16_t  i = 0; // max value is 1 << 8 + 1

    memset(&q->domain_name[0], 0, sizeof(q->domain_name));
    memset(&q->record_type, 0, sizeof (uint16_t));
    memset(&q->class, 0, sizeof (uint16_t));

    q->record_type = 0;
    q->class = 0;

    // 16 bit is enough to count the subdomains
    uint16_t subdomain_count = 0;

    for (i=0; i < (int) 255; i++){
        if (cursor + 1 > mem_end) {
#ifdef  DEBUG
            bpf_printk("Error the Reading out for a unsafe mem location");
#endif
            break;
        }

        // check for the null length termination at the end, reached the string end
        if (*(char *) cursor == 0){
            if (cursor + 5 > mem_end){
#ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
#endif
            } else {
                q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
                q->class = bpf_htons(*(uint16_t *)(cursor + 3));
            }
            return namepos + 2 + 2 + 1; // handle the mem offsets
        }

        q->domain_name[namepos] = *(char *)cursor;
        int val = (int) q->domain_name[namepos];

        if (val <= 20)
            q->domain_name[namepos] = (char ) '.';

        if (strlen((char *) cursor) == 0) bpf_printk("A null value found need to espace it");
        else
            bpf_printk("Bufffer value found need that to be processed is %c", q->domain_name[namepos]);

        if (__verify_sub_domain_count(&q->domain_name[namepos])) subdomain_count++;
        namepos++;
        cursor++;
    }
    subdomain_count--; // remove the delimeter in the domain count
    __verify_dns_labels(q->domain_name);

    return -1;
}

static
__always_inline int __parse_dns_answer_sections(struct xdp_md *skb, void *extra_dns_data_section,
            struct dns_query_section *q){

    return -1;
}

static
__always_inline int __parse_dns_addon_sections(struct xdp_md *skb, void *extra_dns_data_section, struct dns_query_section *q){
    return -1;
}


// pass the latest order buffer for top 2 layers of the protocol
static
__always_inline bool __parse_dns_spoof(struct udphdr *udp_hdr, struct xdp_md *skb, struct iphdr *ip){
    uint16_t dest = bpf_ntohs(udp_hdr->dest);

    bpf_printk("A UDP Packet was found and loaded Possibly DNS %u", dest);
    switch (ip->protocol) {
        case IPPROTO_IP: {
            uint32_t val = bpf_ntohs(ip->saddr);
            uint64_t  time = bpf_ktime_get_ns();
        }
        case IPPROTO_IPV6: {}
    }

    if (dest == 53) {
        uint64_t buff = 10;
        uint64_t *value = bpf_map_lookup_elem(&dnsBuffer, &buff);
        if (value) (*value)++;
        else {
            uint64_t count = 1;
            bpf_map_update_elem(&dnsBuffer, &buff, &count, BPF_ANY);
        }
        uint64_t *updated_value;
        updated_value =  bpf_map_lookup_elem(&dnsBuffer, &buff);

        if (updated_value)
            bpf_printk("The Map DNS Data is %u", *updated_value);
        void * dns_head = (void *) udp_hdr + sizeof (udp_hdr);

        struct dns_header *dnsHeader = dns_head;
        if ((void *) dnsHeader + sizeof (struct dns_header) > (void *) skb->data_end){
            #ifdef DEBUG
                bpf_printk("The header length for the payload exceed the max range");
            #endif
            return false;
        }
        else {
            void *extra_dns_data_section = (void *) dnsHeader + sizeof (struct dns_header);
            if ((void *) extra_dns_data_section + sizeof (struct dns_header) > (void *) skb->data_end){
                return false;
            }
            struct dns_query_section querySection;

            if (dnsHeader->qd_count == 1 && dnsHeader->ans_count == 0){
                // possibly the malware is trying to do exfiltration to get attacker's ip address a ipv4 or ipv6 from A type domain
                // to the attacker's namesapce

                __parse_dns_query_sections(skb,  extra_dns_data_section, &querySection);

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
                uint32_t  proc_id  = bpf_get_smp_processor_id();
                bpf_printk("The processing running the program is %u32", proc_id);
                bpf_printk("%u %u", ntohs(dnsHeader->qd_count), ntohs(dnsHeader->ans_count));
            }else if (dnsHeader->qd_count >= 1
                    || dnsHeader -> ans_count >= 1){
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
