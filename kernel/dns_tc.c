#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/pkt_cls.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "dns.h"
#include "consts.h"
#include "utils.h" 

#define SIZE_INFO(ptr, data, end) \
    if ((void *) ptr + sizeof(data) > end) return TC_ACT_SHOT;

#define PRINT_DEBUG(fmt, ...) bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__)

#ifndef tc
    #define TC_FORWARD TC_ACT_OK
    #define TC_DEFAULT TC_ACT_UNSPEC
    #define TC_DROP TC_ACT_SHOT
#endif


#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CHECK_FF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_CHECK_FF_V6 (ETH_HLEN + offsetof(struct ipv6hdr, check))

#define UDP_CHECK_FF (ETH_HLEN + offsetof(struct udphdr, check))
#define TCP_CHECK_FF (ETH_HLEN + offsetof(struct tcphdr, check))

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

struct skb_cursor {
    void *data;
    void *data_end;
};

struct vlanhdr {
	__u16 tci;
	__u16 encap_proto;
};

struct packet_actions {
    bool (*cursor_init) (struct skb_cursor *, struct __sk_buff *);
    struct packet_actions (*packet_class_action) (struct packet_actions actions);
    // link layer
    __u8 (*parse_eth) (struct skb_cursor *);
    // router layer 3
    __u8 (*parse_ipv4) (struct skb_cursor *);
    __u8 (*parse_ipv6) (struct skb_cursor *);
    // transport layer 4 
    __u8 (*parse_udp) (struct skb_cursor *, bool);
    __u8 (*parse_tcp) (struct skb_cursor *, bool);
    /* 
        Each layer 4 parsing overthe header is processed with the previous layer header size offset 
    */
    
    // app layer 
    __u8 (*parse_dns_header_size) (struct skb_cursor *, bool, bool, __u32 );
    __u8 (*parse_dns_payload) (struct skb_cursor *, void *, __u32, __u32,  bool, bool, struct dns_header *, __u32);
    __u8 (*parse_dns_payload_memsafet_payload) (struct skb_cursor *, void *, struct dns_header *); // standard dns port DPI with header always assured to be a DNS Header and dns payload 

    // dns header parser section fro the enitr query labels 
    __u8 (*parse_dns_payload_queries_section) (struct skb_cursor *, __u16, struct qtypes );

    // the malware can use non standard ports perform DPI with non statandard ports for DPI inside kernel matching the dns header payload section;
    __u8 (*parse_dns_payload_non_standard_port) (struct skb_cursor * , void *, struct dns_header *, bool);

    // final and complete DPI over the dns and events submit 
    __u8 (*__dns_dpi) (struct skb_cursor , struct __sk_buff *, struct packet_actions , 
                __u32 , void * , __u32  , bool , bool );
};

__u32 INSECURE = 0;

/* ***************************************** Event ring buffeers for kernel detected DNS events ***************************************** */

// ring buffer event from kernel storing information for the packet dropped within the kernel 
struct exfil_security_egress_drop_ring_buff {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} exfil_security_egress_drop_ring_buff SEC(".maps");


/* ***************************************** Event maps for kernel ***************************************** */
// make the map struct more fine grained to prevent timing attacks from user space malware 
struct checkSum_redirect_struct_value {
    __u16 checksum; // the l3 checksum for the kernel packet before redirection 
    __u64 kernel_timets; // 
};

// stores inofrmation regarding checksum and the redirection of the packet from kernel 
struct exfil_security_egress_redirect_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16); // dns query id prior DPI
    __type(value, struct checkSum_redirect_struct_value);   // layer 3 checksum prior redirect using a non clone skb redirect 
    __uint(max_entries, 1 << 24);
} exfil_security_egress_redirect_map SEC(".maps");

struct exfil_security_egress_redurect_ts_verify {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64); // store the timestamp loaded from userspace when pacekt hits 
    __type(value, __u8);   // layer 4 checksum prior redirect non clone skb 
    __uint(max_entries, 1);
} exfil_security_egress_redurect_ts_verify SEC(".maps");

// count the number of packets 
struct exfil_security_egress_redirect_count_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);  // dns dest target ip over redirection  // usually the host subnet cidr gateway
    __type(value, __u32);   // count of hte packet for multiple redirection 
    __uint(max_entries, 1);
} exfil_security_egress_redirect_count_map SEC(".maps");


/* ***************************************** Event maps for Egress Traffiic Rate Limiting ***************************************** */
struct dns_volume_stats {
    __u64 last_timestamp;
    __u32 packet_size;
};

// exfil rate limiter 
// follows leaky bucket algortihm with ebpf lru map inside kernel operating anf moniting dns traffic over single window 
// the packet does not matter (dns + tcpv4 / tcpv6) or (dns + udpv4 + udpv6)
struct exfil_security_egress_rate_limit_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);
    __type(value, struct dns_volume_stats);
    __uint(max_entries, 1);
} exfil_security_egress_rate_limit_map SEC(".maps");


static 
__always_inline bool cursor_init(struct skb_cursor *cursor, struct __sk_buff *skb){
    cursor->data = (void *)(ll)(skb->data);
    cursor->data_end = (void *)(ll)(skb->data_end);
    return true;  // Added return statement
}

static 
__always_inline __u8 parse_eth(struct skb_cursor *skb) {
    struct ethhdr *eth = skb->data;
    if ((void *) (eth + 1) > skb->data_end) return 0;  // should strictly be in skb kernel boundary
    return 1;
}

static 
__always_inline __u8 parse_ipv4(struct skb_cursor *skb) {
    struct iphdr *ip = skb->data + sizeof(struct ethhdr);

    if ((void *) (ip + 1) > skb->data_end ) return 0; // should strictly be in skb kernel boundary
  
    return 1;
}

static 
__always_inline __u8 parse_ipv6(struct skb_cursor *skb) {
    struct ipv6hdr *ipv6 = skb->data + sizeof(struct ethhdr);
    if ((void *)(ipv6 + 1) > skb->data_end) return 0;
    return 1;
}

static 
__always_inline __u8 process_udp_payload_mem_verification(struct udphdr *udp, struct skb_cursor *skb, bool isIPv4) {
    __u16 udp_len = bpf_ntohs(udp->len);
    __u16 udp_len_payload = udp_len - sizeof(struct udphdr); // Ensure payload size is valid

    // Pointer to the start of the UDP payload
    void *udp_data = skb->data + sizeof(struct ethhdr) + (isIPv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) + sizeof(struct udphdr);

    // Check if the UDP payload fits within the packet
    if ((void *)udp_data + udp_len_payload > skb->data_end) {
        #ifdef DEBUG
            if (DEBUG)
                bpf_printk("UDP payload exceeds packet boundary");
        #endif
        return 0;  // Return error for the kernel memory limit exceed for memory safety 
    }

    // Check if the UDP payload fits within the packet
    if ((void *)udp_data + udp_len_payload > skb->data_end) {
        bpf_printk("UDP payload exceeds packet boundary");
        return 0;  // Return error for the kernel memory limit exceed for memory safety 
    }

    return 1;
}


static 
__always_inline __u8 parse_udp(struct  skb_cursor *skb, bool isIpv4) {
    struct udphdr *udp = skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    if ((void *)(udp + 1) > skb->data_end) return 0;

    if (process_udp_payload_mem_verification(udp, skb, isIpv4 ? true : false) == 0) 
        return 0;
    

    #ifdef DEBUG
        if (DEBUG) {
            __u16 dport = bpf_htons(udp->dest);
            __u16 sport = bpf_htons(udp->source);
            bpf_printk("The Dest and src port for UDP packet are %u %u", dport, sport);
        }
    #endif

    return 1;
}

static 
__always_inline __u8 parse_tcp(struct  skb_cursor *skb, bool isIpv4) {
    struct tcphdr *tcp = skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    if ((void *)(tcp+ 1) > skb->data_end) return 0;

    #ifdef DEBUG
        if (DEBUG) {
            __u16 dport = bpf_htons(tcp->dest);
            __u16 sport = bpf_htons(tcp->source);
            bpf_printk("The Dest and src port for TCP packet are %u %u", dport, sport);
        }
    #endif

    return 1;
}

static 
__always_inline __u8 parse_dns_header_size(struct skb_cursor *skb, bool isIpv4, bool isTcp, __u32 udp_payload_exclude_header) {
    // verify the dns header payload from root of the skbuff 


    /*
        TODO: Need to think about other layer 7 protocols and their memory safety for size
    */
    if (skb->data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + sizeof(struct dns_header) > skb->data_end) {
        // this is definitely not a layer 7 dns header allow this to be classified for a valid action 
        return 1;
    }

    // the size of the header is matching for dns header must be  a dns header for ipv4 
    struct dns_header *dns_hdr = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    #ifdef DEBUG 
        if (DEBUG) {
            bpf_printk("the info for dns question is %u and answercount %u", bpf_ntohs(dns_hdr->qd_count), bpf_ntohs(dns_hdr->ans_count));
            if (bpf_ntohs(dns_hdr->add_count) > 0) {
                #pragma unroll(255)
                for (__u8 i=0; i < (1 << 8); i++){}
            }
            bpf_printk("the addon count %u", bpf_ntohs(dns_hdr->add_count));
        }
    #endif

    return 1;
}


static 
__always_inline __u8 parse_dns_payload(struct skb_cursor *skb, void * dns_payload, 
            __u32 udp_payload_len, __u32 udp_payload_exclude_header,  bool ispv4, bool isUdp,  struct dns_header * dns_header, __u32 skb_len) {
        
        // the kernel verifier enforce and need to be strict and assume the buffer is validated before itself 

        if (udp_payload_len > skb_len || udp_payload_exclude_header > skb_len) return 0;

        #ifdef DEBUG 
            if (DEBUG){
                bpf_printk("The size of the dns payload %u and buffer %u and pyload %u", sizeof(*dns_payload), udp_payload_exclude_header, bpf_htons(dns_header->ans_count));
            } 
        #endif

        return 1;
}

static
  __always_inline __u8 parse_dns_qeury_type_section(struct skb_cursor *skb, __u16 dns_query_class, struct qtypes qt) {

       
        switch (dns_query_class){
            case 0x0001: 
            case 0x0002:
            case 0x0005:
            case 0x0006: 
            case 0x001C: 
            case 0x0041:
                return BENIGN;
            case 0x000F:
            case 0x0021:
            case 0x0023:
            case 0x0029: 
                return SUSPICIOUS;
            case 0x0010:
            case 0x00FF:
                return MALICIOUS;
            default: {
                return SUSPICIOUS;
            }
        }
        return SUSPICIOUS;
  }

static 
__always_inline __u8 parse_dns_payload_memsafet_payload(struct skb_cursor *skb, void *dns_payload, struct dns_header *dns_header) {
    // dns header already validated and payload and header memory safetyy already cosnidered 

    // debug the size and content of questions, answer auth and add count in dns header 

    struct dns_flags  flags = get_dns_flags(dns_header);
    #ifdef DEBUG
        if (DEBUG) {
        bpf_printk("the auth question count are %u %u", bpf_ntohs(dns_header->qd_count), bpf_ntohs(dns_header->ans_count));
        bpf_printk("the addon question count are %u %u", bpf_ntohs(dns_header->add_count), bpf_ntohs(dns_header->auth_count));
        bpf_printk("the query opcode %d",  flags.opcode);
        }
    #endif

    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    // the size of char containing the dns payload char size 
    __u8 *dns_payload_buffer = (__u8 *) dns_payload;
    /*
        Usually a dns resolvert sends 1 requestt query for a single request to the remote DNS server 
        The clsact qdisc is only meant for egress traffic and tc control flow system after fa_codel and default tc action from kernel
        Direct action appled over the egress traffic 
        DNS exfiltration attacks, malware can hide and transmit data not only in the questions section of DNS queries but also in other sections, making it more flexible and stealthy
    */

   if (qd_count == 1) {
     if (ans_count == 0) {
        // a questions record and its an benign packet but need DPI and kernel can do DPI for the entire packet frame 
        qd_count = 1; // let the ebpf verifier proceed during JIT and memory check 

        if (auth_count >= 1) {
            return SUSPICIOUS;
        }

        if (add_count > 1) return SUSPICIOUS;

        // for EDNS servers the request can sedn auth OPT records allow to pass through the kernel 
        int oc = 0;
        
        // bpf_printk("[x] Performing DPI over the single question section for DPI inside Kernel");
        for (__u8 i=0; i < qd_count; i++){
            __u16 offset = 0;
            __u8 label_count = 0; __u8 mx_label_ln = 0;
            __u8 total_domain_length_exclude_tld = 0; // excluding auth root domain information 

            __u8 root_domain  = 0; //domain tld + auth root zone domain 
            
            __u8 char_count = 0; __u8 num_count = 0;
            for (int j = 0; j < MAX_DNS_NAME_LENGTH; j++) {
                if ((void *) (dns_payload_buffer + offset + 1) > skb->data_end) return SUSPICIOUS;

                __u8 label_len = *(__u8 *) (dns_payload_buffer + offset);

                mx_label_ln = max(mx_label_ln, label_len);
                if (label_len == 0x00) break;

                label_count++;
                if (label_len >= DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_PER_LABEL && label_len <= DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_PER_LABEL){
                    return SUSPICIOUS;
                }
                    
                if (root_domain > 2){
                    total_domain_length_exclude_tld += label_len;
                    __u16 char_label_offset = offset + 1;
                    label_len = label_len >= DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_PER_LABEL ? DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_PER_LABEL 
                            : label_len;   
                }
                else 
                    root_domain++;

                offset += label_len + 1;
                if ((void *) (dns_payload_buffer + offset) > skb->data_end) return SUSPICIOUS;
            }

            // parse the remaining and left over 2 bytes from the processed header for query type to be at offset end of the query label 
            __u16 query_type; __u16 query_class;
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;
            query_type = *(__u16 *) (dns_payload_buffer + offset); 
            
            offset += sizeof(__u16);
            if ((void *) (dns_payload_buffer + offset + sizeof(__u16)) > skb->data_end) return SUSPICIOUS;
            
            query_class = *(__u16 *) (dns_payload_buffer + offset);
            offset += sizeof(__u16); // offset += sizeof(__u8) + 1;

            __u8 subdmoain_label_count = root_domain == 2 ? 0 : label_count - 2;

            #ifdef DEBUG
                if (DEBUG) {
                    bpf_printk("the label count is %u and mx label len %u", label_count, mx_label_ln); 
                    bpf_printk("the query type is %d and class is %d", query_type, query_class);
                    bpf_printk("the total domain length is %d ", total_domain_length_exclude_tld);
                }
            #endif

            if (label_count <= 2) return BENIGN;

            if (label_count > DNS_RECORD_LIMITS.MIN_LABEL_COUNT && label_count <= DNS_RECORD_LIMITS.MAX_LABEL_COUNT){

                if (subdmoain_label_count >= DNS_RECORD_LIMITS.MIN_SUBDOMAIN_LENGTH_EXCLUDING_TLD  && 
                                    subdmoain_label_count <= DNS_RECORD_LIMITS.MAX_SUBDOMAIN_LENGTH_EXCLUDING_TLD) {}
                // bpf_printk("invoked on  label_count %d", label_count);
                return SUSPICIOUS;
            }
            
            if (total_domain_length_exclude_tld >= DNS_RECORD_LIMITS.MIN_DOMAIN_LENGTH && total_domain_length_exclude_tld <= DNS_RECORD_LIMITS.MAX_DOMAIN_LENGTH){
                // bpf_printk("invoked on  total domain length %d", total_domain_length_exclude_tld);
                return SUSPICIOUS;
            }
            
            return parse_dns_qeury_type_section(skb, query_class, qtypes);
        }
     }else return SUSPICIOUS;
   }else {
        /// the question is malicious since the malicious client is sending multiple questions a C2C where malware is asking next commands 
        return SUSPICIOUS;
   }

   return BENIGN;
}   



static 
__always_inline __u8 parse_dns_payload_non_standard_port(struct skb_cursor * skb, void *dns_payload, 
                struct dns_header *dns_header, bool isUDP) {
    // check whether a non standard port is used for dns query and dns payload 
    
    struct dns_flags  flags = get_dns_flags(dns_header);

    // qeuries section 
    __u16 qd_count = bpf_ntohs(dns_header->qd_count);
    __u16 ans_count = bpf_ntohs(dns_header->ans_count);
    __u16 auth_count = bpf_ntohs(dns_header->auth_count);   
    __u16 add_count = bpf_ntohs(dns_header->add_count);

    //bpf_printk("NON STANDARD Port used over similar dns standard header further DPI %u %u", qd_count, ans_count);
    if (qd_count >= (1 << 8) - 1 || ans_count >= (1 << 8) - 1 || auth_count >= (1 << 8) - 1 || add_count >= (1 << 8) - 1) {
        // the dns payload is non standard port and the protcol encapsulated used is not dns 
        return 1;
    }

    // a malicious encap is used to mask the dns traffPic 
    return 0;
}

static 
__always_inline __u8 __parse_skb_non_standard(struct skb_cursor cursor, struct __sk_buff *skb, struct packet_actions actions, 
                    __u32 udp_payload_exclude_header, void *udp_data, __u32 udp_payload_len, bool isIpv4, bool isUdp) {
      // always forward from kernel if the packet is using a non standard udp port and trying to send a dns packet over non standard port 
        if (actions.parse_dns_header_size(&cursor, isIpv4 ? true : false, isUdp ? true : false ,udp_payload_exclude_header) == 0)
            // an non dns protocol based udp packet (no dns header found) 
            return 1;
        
        
        void *dns_payload = cursor.data + sizeof(struct ethhdr) + (isIpv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) + 
                            (isUdp ? sizeof(struct udphdr) : sizeof(struct tcphdr)) + sizeof(struct dns_header);
        if ((void *) (dns_payload + 1) > cursor.data_end) return TC_FORWARD;
        struct dns_header *dns = (struct dns_header *) (udp_data);
        if (actions.parse_dns_payload(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, isIpv4 ? true : false, isUdp ? true : false
                         , dns, skb->len) == 0) 
            return 1;
        
        // get the dns flags from the dns header 
        struct dns_flags flags = get_dns_flags(dns);
        
        #ifdef DEBUG 
          if (DEBUG) {
            bpf_printk("DNS packet found header %u %u", bpf_ntohl(dns->qd_count), bpf_ntohl(dns->ans_count));
          }
        #endif
        __u8 action_non_port = actions.parse_dns_payload_non_standard_port(&cursor, dns_payload, dns, true);
        // bpf_printk("NON PORT ACTION %u", action_non_port);
        // encap packet used and normally this packet are not used for dns query 
        return 1;
        // do deep packet inspection on the packet contett and the associated payload 
}


static 
__always_inline __u8 __dns_dpi(struct skb_cursor cursor, struct __sk_buff *skb, struct packet_actions actions, 
                __u32 udp_payload_exclude_header, void * udp_data, __u32 udp_payload_len , bool isIpv4, bool isUdp){
    return 1;
}


static 
__always_inline __u8 __dns_rate_limit(struct skb_cursor *cursor, struct __sk_buff *skb, __u16 dns_payload_size){
    
    __u16 key = 0;
    __u64 ts = bpf_ktime_get_ns();


    struct dns_volume_stats *dns_volume_stats = bpf_map_lookup_elem(&exfil_security_egress_rate_limit_map, &key);
    if (!dns_volume_stats) {
        struct dns_volume_stats stats = {
            .packet_size = (__u64) dns_payload_size,
            .last_timestamp = ts
        };
        bpf_map_update_elem(&exfil_security_egress_rate_limit_map, &key, &stats, BPF_ANY);
        return 1;
    }

    if (ts - dns_volume_stats->last_timestamp > TIMEWINDOW) {
        dns_volume_stats->last_timestamp = ts;
        dns_volume_stats->packet_size = (__u64) dns_payload_size;
    }else {
        dns_volume_stats->packet_size += dns_payload_size;
        #ifdef DEBUG
            if (DEBUG) {
                bpf_printk("current packet threshold is %u",  dns_volume_stats->packet_size);
            }
        #endif
    }

    if (ts - dns_volume_stats->last_timestamp <= TIMEWINDOW && dns_volume_stats->packet_size > MAX_VOLUME_THRESHOLD){
        #ifdef DEBUG
            if (DEBUG) {
                bpf_printk("kernel started rate limiting the packets for egress");
            }
        #endif
        return 0;
    }else 
        dns_volume_stats->last_timestamp = ts;
    return 1;
}


static 
__always_inline struct packet_actions packet_class_action(struct packet_actions actions) {
    actions.cursor_init = &cursor_init;
    actions.parse_eth = &parse_eth;
    actions.parse_ipv4 = &parse_ipv4;
    actions.parse_ipv6 = &parse_ipv6;
    actions.parse_udp = &parse_udp;
    actions.parse_tcp = &parse_tcp;
    actions.parse_dns_header_size = &parse_dns_header_size;
    actions.parse_dns_payload = &parse_dns_payload;
    actions.parse_dns_payload_memsafet_payload = &parse_dns_payload_memsafet_payload;
    actions.parse_dns_payload_non_standard_port = &parse_dns_payload_non_standard_port;
    actions.parse_dns_payload_queries_section = &parse_dns_qeury_type_section;
    actions.__dns_dpi = &__dns_dpi;
    return actions;
}


struct payload_data {
  __u32 len;
  __u8 data[1500]; 
};

struct kernel_handler_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u8);
    __type(value, __u16);
} maps SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}


static long callback_fn(struct bpf_map *map, const void *key, void *value, void *ctx) {
    bpf_printk("[x] // looping over the  map for kernel exfil config ");

    bpf_printk("the key is ", *(__u32 *) key);
    bpf_printk("the value is ", *(__be32 *) key);

    return 0;
}

SEC("tc")
int classify(struct __sk_buff *skb){
    
    struct skb_cursor cursor; 
    struct packet_actions actions;

    actions.packet_class_action = &packet_class_action;
    actions = actions.packet_class_action(actions);

    struct ethhdr *eth;
    struct iphdr *ip; 
    struct ipv6hdr *ipv6; 

    // Initialize cursor and parse Ethernet header
    actions.cursor_init(&cursor, skb);
    if (actions.parse_eth(&cursor) == 0) return TC_DROP;
    eth = cursor.data;
    __u32 nhoff = ETH_HLEN;

	// bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

    struct udphdr *udp; struct tcphdr *tcp;

    // Parse IPv4 or IPv6 based on Ethernet protocol type
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        if (actions.parse_ipv4(&cursor) == 0) return TC_DROP;
        ip = cursor.data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > cursor.data_end) return TC_DROP;

        if (ip_is_fragment(skb, nhoff)) return TC_DROP;

        if (ip->protocol == IPPROTO_UDP) {
            if (actions.parse_udp(&cursor, true) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) udp + 1 > cursor.data_end) return TC_DROP;
            void * udp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            if ((void *) udp_data + 1 > cursor.data_end) return TC_DROP;

            __u32 total_offset = nhoff + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (total_offset > skb->len) return TC_DROP;
            __u32 udp_payload_len = bpf_ntohs(udp->len);
            __u32 udp_payload_exclude_header = udp_payload_len - sizeof(struct udphdr);

            // its definitely a dns udp packet but make sure for deep scannign for mem safety
            if (udp->dest == bpf_htons(DNS_EGRESS_PORT)) {

                if (actions.parse_dns_header_size(&cursor, true, true, udp_payload_exclude_header) == 0)
                    return TC_DROP;

                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
                if ((void *) (dns_payload + 1) > cursor.data_end) return TC_DROP;
                struct dns_header *dns = (struct dns_header *) (udp_data);

                if (actions.parse_dns_payload(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, true, true, dns, skb->len) == 0) {
                    return TC_DROP;
                }


                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload(&cursor, dns_payload, dns);
        
                bool deep_scan_mirror = false;
                bool drop = false;
                bool isBenign = false;
                switch (parse_flag) {
                    case SUSPICIOUS: {
                        deep_scan_mirror = true;
                        break;
                    }
                    case MALICIOUS: {
                        drop = true;
                        break;
                    }
                    case BENIGN: {
                        isBenign = true;
                        break;
                    }
                    default: {
                        deep_scan_mirror = true;
                        break;
                    }
                }

                if (deep_scan_mirror){
                    bpf_printk("Suspicious pacekt found perform DPI in UDP Layer over Ipv4 for action flag %u", parse_flag);
                } 

                __be32 current_dest_addr; 
                __be32 dest_addr_route = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4);
                __be32 dest_addr_route_malicious = bpf_ntohl(BRIDGE_REDIRECT_ADDRESS_IPV4_MALICIOUS);

                __u32 out = skb->ifindex;

                struct exfil_kernel_config *config = bpf_map_lookup_elem(&exfil_security_config_map, &out); // 10.200.0.1
                __u32 br_index = 4; 

                if (config) {
                    __be32 redirect_address_from_config = config->RedirectIpv4;
                    dest_addr_route = bpf_htonl(redirect_address_from_config);
                    br_index = config->BridgeIndexId;
                    bpf_printk("kernel config loaded from node agent for redirect and bridge index %u %u", redirect_address_from_config, config->BridgeIndexId);
                }else {
                    bpf_printk("kernel cannot find the requred kernel config redirect map");
                }

                //  layer 7 rate limiting of the packet inside kernel 
                __u16 dns_payload_size = udp_payload_exclude_header;
                if (deep_scan_mirror) {
                    __u8 dns_rate_limit_action = __dns_rate_limit(&cursor, skb, dns_payload_size);

                    #ifdef DEBUG
                        if (DEBUG) {
                            bpf_printk("the rate limit action is %u", dns_rate_limit_action);
                        }
                    #endif
                    if (dns_rate_limit_action == 0) return TC_DROP;
                }
            

                if (isBenign) {
                    #ifdef DEBUG
                        if (DEBUG) {
                            bpf_printk("Allowing the packet as benign with no further DPI from kernel"); 
                        }
                    #endif
                    return TC_FORWARD;
                }
                else if (drop){
                    #ifdef DEBUG 
                        if (DEBUG) {
                            bpf_printk("Dropping the packet in Kernel Layer");
                        }
                    #endif

                    if (bpf_skb_load_bytes(skb, IP_DST_OFF, &current_dest_addr, 4) < 0) {
                        bpf_printk("Error Loading the IP Destination Address for malicious redirect"); 
                        return TC_DROP;
                    } 
                    __u32 csum_diff_drop = bpf_csum_diff(&current_dest_addr, 4, &dest_addr_route_malicious, 4, 0);

                    if (IP_DST_OFF > skb->len) {
                        return TC_DROP;  // Check if offset is within bounds
                    }

                    if (bpf_l3_csum_replace(skb, IP_CHECK_FF, 0, csum_diff_drop, 0) < 0) {
                            return TC_FORWARD;
                    }


                    if (bpf_skb_store_bytes(skb, IP_DST_OFF, &dest_addr_route, sizeof(dest_addr_route), 0) < 0) {
                        return TC_FORWARD;
                    }

                    if (skb->mark != (__u32) redirect_skb_mark) {
                        if (DEBUG) {
                            bpf_printk("Marking the packet over kernel redirection for DPI");
                        }
                        skb->mark = redirect_skb_mark;
                    }

                    return bpf_redirect(br_index, dest_addr_route);
                }

                // perform dpi here and mirror the packet using bpf_redirect over veth kernel bridge for veth interface 
                __u16 transaction_id = (__u16) bpf_ntohs(dns->transaction_id);
                __u16 ip_checksum = bpf_ntohs(ip->check);
                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
                    struct checkSum_redirect_struct_value layer3_checksum = {
                        .checksum =  ip_checksum, 
                        .kernel_timets = bpf_ktime_get_ns(),
                    };
                    // Key not found, insert new element for the dns query id mapped to layer 3 checksum
                    int ret = bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum, BPF_ANY);
                    if (ret < 0) {
                        if (DEBUG){
                            bpf_printk("Error updating the bpf redirect from tc kernel layer");
                        }
                    }
                } else {
                    if (DEBUG){
                        bpf_printk("[x] An Layer 3 Service redirect from the kernel and pakcet fully scanned now can be removed");
                    }

                    bpf_map_delete_elem(&exfil_security_egress_redirect_map, &transaction_id);
                    __u8 * pres;
                    __u64 packet_kernel_ts = map_layer3_redirect_value->kernel_timets;
                    pres = bpf_map_lookup_elem(&exfil_security_egress_redurect_ts_verify, &packet_kernel_ts);
                    if (pres) {
                        bpf_map_delete_elem(&exfil_security_egress_redurect_ts_verify, &packet_kernel_ts);
                        return TC_FORWARD; // scanned from the kernel bufffer proceeed with forward passing to desired dest;
                    }else {
                        #ifdef DEBUG 
                            if (DEBUG) {
                                bpf_printk("the kernel verified timing attack broke and was not  \
                                                 prevented it with ns timestamp verification after DPI");
                            }
                        #endif
                        return TC_FORWARD;
                    }
                }

                __u16 redirection_count_key = 0; // keep constant from kernel to measure the redirection count 
                __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key);
                if (ct_val) {
                    __sync_fetch_and_add(ct_val, 1); // increase redirection buffer count
                }else {
                    __u32 init_map_redirect_count = 1;
                    bpf_map_update_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
                }

                // change the dest ip to point to the bridge for destination over the internal subnet of network namespaces

                if (bpf_skb_load_bytes(skb, IP_DST_OFF, &current_dest_addr, 4) < 0) {
                    // 4 bytes for the ipv4 address offset 
                    #ifdef DEBUG   
                        if (DEBUG) {
                            bpf_printk("Error restoring current offset store");
                        }
                    #endif
                } 
                __u32 csum_diff = bpf_csum_diff(&current_dest_addr, 4, &dest_addr_route, 4, 0);

                if (IP_DST_OFF > skb->len) {
                    return TC_DROP;  // Check if offset is within bounds
                }

                if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), 0, csum_diff, 0) < 0) {
                        return TC_FORWARD;
                }


                if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &dest_addr_route, sizeof(dest_addr_route), 0) < 0) {
                    return TC_FORWARD;
                }

                if (skb->mark != (__u32) redirect_skb_mark) {
                    if (DEBUG) {
                        bpf_printk("Marking the packet over kernel redirection for DPI");
                    }
                    skb->mark = redirect_skb_mark;
                }
    
                
                return bpf_redirect(br_index, BPF_F_INGRESS); // redirect to the bridge
                // for now learn dns ring buff event;
            }else if (udp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)){
                return TC_FORWARD;
            }else {
                if (__parse_skb_non_standard(cursor, skb, actions, udp_payload_exclude_header, 
                                    udp_data, udp_payload_len, true, true) == 1) 
                    return TC_FORWARD;
                return TC_DROP;
            }
            return TC_FORWARD;
        }else if (ip->protocol == IPPROTO_TCP) {
            if (actions.parse_tcp(&cursor, true) == 0) return TC_DROP;
            tcp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) (tcp + 1) > cursor.data_end) return TC_DROP;

            void *tcp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            if ((void *) tcp_data + 1 > cursor.data_end) return TC_DROP;

            // verify for standard or enhanced dpi inspection over the payload header 
            if (tcp-> dest == bpf_htons(DNS_EGRESS_PORT)) {
                // a standard port used for tcp data forwarding 
                void *dns_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct dns_header);
                if ((void *) dns_data + 1 > cursor.data_end) return TC_DROP;
                return TC_FORWARD;
            }else {

            }

            return TC_FORWARD;
        }
	}else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ipv6 = cursor.data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > cursor.data_end) return TC_DROP;
        
        if (ip->protocol == IPPROTO_UDP) {
            if (actions.parse_udp(&cursor, false) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if ((void *) udp + 1 > cursor.data_end) return TC_DROP;
            void * udp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            if ((void *) udp_data + 1 > cursor.data_end) return TC_DROP;

            __u32 total_offset = nhoff + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            if (total_offset > skb->len) return TC_DROP;
            __u32 udp_payload_len = bpf_ntohs(udp->len);
            __u32 udp_payload_exclude_header = udp_payload_len - sizeof(struct udphdr);
       
            if (udp->dest == bpf_ntohs(DNS_EGRESS_PORT)) {
                if (actions.parse_dns_header_size(&cursor, true, true, udp_payload_exclude_header) == 0)
                    return TC_DROP;
                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
                if ((void *) dns_payload + 1 > cursor.data_end) return TC_DROP; 
                struct dns_header *dns = (struct dns_header *) (udp_data);

                if (actions.parse_dns_payload(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, true, true, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                // reached app layer no offset processing required from kernel 
                __u8 parse_flag = actions.parse_dns_payload_memsafet_payload(&cursor, dns_payload, dns);

                bool deep_scan_mirror = false;
                bool drop = false;
                bool isBenign = false;
                switch (parse_flag) {
                    case SUSPICIOUS: {
                        deep_scan_mirror = true; break;
                    }
                    case MALICIOUS: {
                        drop = true; break;
                    }
                    case BENIGN: {
                        isBenign = true; break;
                    }
                    default: {
                        deep_scan_mirror = true; break;
                    }
                }

                if (deep_scan_mirror){
                    bpf_printk("Suspicious pacekt found perform DPI UDP Layer over Ipv6 for action flag %u", parse_flag);
                } 

                //  layer 7 rate limiting of the packet inside kernel 
                __u16 dns_payload_size = udp_payload_exclude_header;
                if (deep_scan_mirror) {
                    __u8 dns_rate_limit_action = __dns_rate_limit(&cursor, skb, dns_payload_size);

                    #ifdef DEBUG
                        if (DEBUG) {
                            bpf_printk("the rate limit action over layer UDP for Ipv6 header action %u", dns);
                        }
                    #endif
                    if (dns_rate_limit_action == 0) return TC_DROP;
                }

                // TODO Add event emit for the drop packet processing 
                if (isBenign) {
                    #ifdef DEBUG 
                        if (DEBUG) {
                            bpf_printk("Benign packet found perform DPI UDP Layer over Ipv6 for action flag %u", parse_flag);
                        }
                    #endif 
                }
                else if (drop) return TC_DROP;

                bpf_printk("A DNS packet was found over IPv6 and using UDP as the transport");
                // perform dpi here and mirror the packet using bpf_redirect over veth kernel bridge for veth interface 
                __u16 transaction_id = (__u16) bpf_ntohs(dns->transaction_id);
                __u16 ip_checksum = bpf_ntohs(ip->check);
                struct checkSum_redirect_struct_value * map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                bool isRedirectFirst = false;
                bool processCloneRedirectRun = false;
                if (!map_layer3_redirect_value) {
                    struct checkSum_redirect_struct_value layer3_checksum = {
                        .checksum =  ip_checksum, 
                        .kernel_timets = bpf_ktime_get_ns(),
                    };
                    // Key not found, insert new element for the dns query id mapped to layer 3 checksum
                    int ret = bpf_map_update_elem(&exfil_security_egress_redirect_map, &transaction_id, &layer3_checksum, BPF_ANY);
                    if (ret < 0) {
                        if (DEBUG){
                            bpf_printk("Error updating the bpf redirect from tc kernel layer");
                        }
                    }
                    isRedirectFirst = true;
                } else {
                    if (DEBUG){
                        bpf_printk("[x] An Layer 3 Service redirect from the kernel and pakcet fully scanned now can be removed");
                    }

                    bpf_map_delete_elem(&exfil_security_egress_redirect_map, &transaction_id);
                    __u8 * pres;
                    __u64 packet_kernel_ts = map_layer3_redirect_value->kernel_timets;
                    pres = bpf_map_lookup_elem(&exfil_security_egress_redurect_ts_verify, &packet_kernel_ts);
                    if (pres) {
                        return TC_FORWARD; // scanned from the kernel bufffer proceeed with forward passing to desired dest;
                    }else {
                        #ifdef DEBUG 
                            if (!DEBUG) {
                                bpf_printk("the kernel verified timing attack broke and was not  \
                                                 prevented it with ns timestamp verification after DPI");
                            }
                        #endif
                        return TC_DROP;
                    }
                }

                __u16 redirection_count_key = 0; // keep constant from kernel to measure the redirection count 
                __u32 *ct_val = bpf_map_lookup_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key);
                if (ct_val) {
                    __sync_fetch_and_add(ct_val, 1); // increase redirection buffer count
                }else {
                    __u32 init_map_redirect_count = 1;
                    bpf_map_update_elem(&exfil_security_egress_redirect_count_map, &redirection_count_key, &init_map_redirect_count, BPF_ANY);
                }

                // TODO need to add the ipv6 checsum recal and packet redirection with u32 * 4 octent sizes stored inside the ipv6 header 
                // forward the traffic for now 

                return TC_FORWARD;

            } else if (udp->dest == bpf_ntohs(DNS_EGRESS_MULTICAST_PORT)) {
                return TC_FORWARD;
            }else {
                if (__parse_skb_non_standard(cursor, skb, actions, udp_payload_exclude_header, udp_data, udp_payload_len, false, true) == 1)
                    return TC_FORWARD;
                return TC_DROP;
            }
            return TC_FORWARD;
        }else if (ip->protocol == IPPROTO_TCP) return TC_FORWARD;
    } else return TC_FORWARD; // likely a kernel vxland packet over the virtual bridge 

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
