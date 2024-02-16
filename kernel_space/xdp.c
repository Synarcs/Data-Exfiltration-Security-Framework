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

/**
 *  Need to use the tail Stack recursion to save some space for the stack in the kernel
 *   Return and use bpf_tail_call for n order tail func call in the bpf stack space.
 */


struct bpf_map_def SEC("maps") dnsBuffer = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(__u64),
        .max_entries = 1 << 10,
};

// please delete the entry from the map once consumed from the user space
struct bpf_map_def SEC("maps") dns_event_buffer = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof (int),
        .value_size = sizeof (struct __domain_event),
        .max_entries = 1024,
};


/**
 *   All the static rule checks that the xdp process handles for processing
 */
static
__always_inline bool __verify_sub_domain_count(char *buffer){
    return true;
}

static
__always_inline bool __verify_sub_domain_length(char *buffer){
    return true;
}

static
__always_inline bool __verify_dns_labels(char *buffer){
    return false;
}

static
__always_inline int __parse_dns_query_sections(struct xdp_md *skb, void *extra_dns_data_section,
                struct dns_query_section *q){
    void *mem_end = (void *) (long) skb->data_end;
    void *curs = extra_dns_data_section;

    int namepos = 0;

    memset(&q->domain_name[0], 0, sizeof(q->domain_name));
    q->record_type = 0;
    q->class = 0;

    for (int i=0; i < (int) 255; i++){
        if (curs + i > mem_end){
#ifdef  DEBUG
            bpf_printk("Error the Reading out for a unsafe mem location");
#endif
            break;
        }
        if (*(char *)(curs) == 0){
            if (curs + 5 > mem_end){
#ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
#endif
            }
            else{
                q->record_type = bpf_htons(*(uint16_t *)(curs + 1));
                q->class = bpf_htons(*(uint16_t *)(curs + 3));
            }
            return namepos + 2 + 2 + 1;
        }
        q->domain_name[namepos] = *(char *)curs;
        namepos++;
        curs++;
    }
    bpf_printk("The domain parsed for the query is %s %u and %c", q->domain_name, q->record_type,  *(char *)q->class);
    return -1;
}

// pass the latest order buffer for top 2 layers of the protocol
static
__always_inline bool __parse_dns_spoof(struct udphdr *udp_hdr, struct xdp_md *skb, struct iphdr *ip){
    bpf_printk("A UDP Packet was found and loaded Possibly DNS %u", ntohs(udp_hdr->dest));
    if (ip->version == 4){
        uint32_t val = bpf_ntohs(ip->saddr);
        uint64_t  time = bpf_ktime_get_ns();


        bpf_printk("The current time is %u64", time);
    }else if (ip->version == 6){

    }

    if (bpf_ntohs(udp_hdr->dest) == 53) {
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
            if (dnsHeader->qd_count >= 1
                    || dnsHeader -> ans_count >= 1){
                struct dns_query_section querySection;

                __parse_dns_query_sections(skb,  extra_dns_data_section, &querySection);
                // only possible is to check for the domain names and lalbels in the domain
                /**
                 * TODO
                 *      check for the labels
                 *      check for the domains names
                 *      check for subdomain count
                 *
                 *      emit the suspicious to user space for stateless packet evaluation using deep learning
                 */
                uint32_t  proc_id  = bpf_get_smp_processor_id();
                bpf_printk("The processing running the program is %u32", proc_id);

//                strcpy(domainEvent.domain, payload);
//                strcpy(domainEvent.classification, type);
                bpf_printk("%u %u", ntohs(dnsHeader->qd_count), ntohs(dnsHeader->ans_count));
            }
        }
        return true;
    }
    return false;
}


SEC("xdp_lb")
int handler(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *ingress = (void *) (long ) ctx->ingress_ifindex;

    struct ethhdr *eth = data;

    if ((void *)eth + sizeof (*eth) > data_end) return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_8021AD) || eth -> h_proto == bpf_htons(ETH_P_8021AD)){}

    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);

        int buffer[100];
        int size = sizeof buffer / sizeof  buffer[0];

        for (int i=0 ; i < size; i++){
            buffer[i] = i * i;
        }

        if ((void *)ip + sizeof(*ip) <= data_end) {
            switch (ip->protocol) {

                case IPPROTO_UDP:
                {
                    struct udphdr *udp = (void *)ip + sizeof(*ip);
                    if ((void *)udp + sizeof(*udp) <= data_end) {
                        if (__parse_dns_spoof(udp, ctx, ip)){
                            return XDP_DROP;
                        }
                        return XDP_PASS;
                    }
                    return XDP_DROP;
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
