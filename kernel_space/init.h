#pragma once

#include <linux/bpf.h>
#include <linux/udp.h>

#include <stdbool.h>



/*
 *  All the XDP Signature defination functions
 */
static __always_inline bool __verify_dns_domain_sperator(char* buffer);
static __always_inline bool __verify_sub_domain_length(int * label_count);
static __always_inline bool __verify_dns_labels(char *buffer);


// header parsers for the bpf header
static __always_inline enum MALICIOUS_FLAGS __parse_dns_query_sections(struct xdp_md *skb, void *extra_dns_data_section, struct dns_query_section *q);
static __always_inline enum MALICIOUS_FLAGS __parse_dns_answer_sections(struct xdp_md *skb, void *extra_dns_data_section, struct dns_query_section *q);
static __always_inline enum MALICIOUS_FLAGS __parse_dns_addon_sections(struct xdp_md *skb, void *extra_dns_data_section, struct dns_query_section *q);


static __always_inline enum XDP_DECISION __parse_dns_spoof(struct udphdr *udp_hdr, struct xdp_md *skb, struct iphdr *ip);
