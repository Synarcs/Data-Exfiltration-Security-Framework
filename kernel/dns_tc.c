#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/pkt_cls.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "dns.h"
#include "consts.h"

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
    __u8 (*parse_udpv4) (struct skb_cursor *);
    __u8 (*parse_udpv6) (struct skb_cursor *);
    __u8 (*parse_tcpv4) (struct skb_cursor *);
    __u8 (*parse_tcpv6) (struct skb_cursor *);

    // app layer 
    __u8 (*parse_dns_header_size) (struct skb_cursor *, bool, __u32 );
    __u8 (*parse_dns_payload) (struct skb_cursor *, void *, __u32, __u32,  bool, struct dns_header *, __u32);
    __u8 (*parse_dns_payload_memsafet_payload) (struct skb_cursor *, void *);
};

__u32 INSECURE = 0;


struct ring_event {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} dns_ring_events SEC(".maps");


struct exfil_security_egress_redirect_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16); // dns query id prior DPI
    __type(value, __u16);   // layer 4 checksum prior redirect non clone skb 
    __uint(max_entries, 1 << 24);
} exfil_security_egress_redirect_map SEC(".maps");

static 
__always_inline bool cursor_init(struct skb_cursor *cursor, struct __sk_buff *skb){
    cursor->data = (void *)(ll)(skb->data);
    cursor->data_end = (void *)(ll)(skb->data_end);
    return true;  // Added return statement
}

static 
__always_inline __u8 parse_eth(struct skb_cursor *skb) {
    struct ethhdr *eth = skb->data;
    if ((void *) (eth + 1) > skb->data_end) return 0; // Proper boundary check
    return 1;
}

static 
__always_inline __u8 parse_ipv4(struct skb_cursor *skb) {
    struct iphdr *ip = skb->data + sizeof(struct ethhdr);

    if ((void *) (ip + 1) > skb->data_end ) return 0; // Proper boundary check
  
    return 1;
}

static 
__always_inline __u8 parse_ipv6(struct skb_cursor *skb) {
    struct iphdr *ipv6 = skb->data + sizeof(struct ethhdr);
    if ((void *)(ipv6 + 1) > skb->data_end) return 1; 
    return 0;
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
__always_inline __u8 parse_udpv4(struct  skb_cursor *skb) {
    struct udphdr *udp = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udp + 1) > skb->data_end) return 0;

    if (process_udp_payload_mem_verification(udp, skb, true) == 0) 
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
__always_inline __u8 parse_udpv6(struct  skb_cursor *skb) {
     struct udphdr *udp = skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)(udp + 1) > skb->data_end) return 1; 


    if (process_udp_payload_mem_verification(udp, skb, false) == 0) 
        return 0;

    #ifdef DEBUG
        if (DEBUG) {
            __u16 dport = bpf_htons(udp->dest);
            __u16 sport = bpf_htons(udp->source);
            bpf_printk("The Dest and src port for UDP packet for Base ipv6 are %u %u", dport, sport);
        }
    #endif

    return 1;
}


static 
__always_inline __u8 parse_tcpv4(struct  skb_cursor *skb) {
    struct tcphdr *tcp = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > skb->data_end) return 1;

    #ifdef DEBUG
        if (DEBUG) {
            __u16 dport = bpf_htons(tcp->dest);
            __u16 sport = bpf_htons(tcp->source);
            bpf_printk("The Dest and src port for TCP packet are %u %u", dport, sport);
        }
    #endif
    return 0;   
}

static 
__always_inline __u8 parse_tcpv6(struct  skb_cursor *skb) {
     struct udphdr *tcp = skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if ((void *)(tcp + 1) > skb->data_end) return 0;
    return 0;   
}


static 
__always_inline __u8 parse_dns_header_size(struct skb_cursor *skb, bool isIpv4, __u32 udp_payload_exclude_header) {
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
        bpf_printk("the info for buffer is %u and id %u", bpf_ntohs(dns_hdr->opcode), bpf_ntohs(dns_hdr->transaction_id));
        bpf_printk("the info for dns question is %u and answercount %u", bpf_ntohs(dns_hdr->qd_count), bpf_ntohs(dns_hdr->ans_count));
        if (bpf_ntohs(dns_hdr->add_count) > 0)
            bpf_printk("the addon count %u", bpf_ntohs(dns_hdr->add_count));
    #endif

    return 1;
}


static 
__always_inline __u8 parse_dns_payload(struct skb_cursor *skb, void * dns_payload, 
            __u32 udp_payload_len, __u32 udp_payload_exclude_header,  bool ispv4, struct dns_header * dns_header, __u32 skb_len) {
        
        // the kernel verifier enforce and need to be strict and assume the buffer is validated before itself 

        if (udp_payload_len > skb_len || udp_payload_exclude_header > skb_len) return 0;

        #ifdef DEBUG 
            bpf_printk("The size of the dns payload %u and buffer %u and pyload %u", sizeof(*dns_payload), udp_payload_exclude_header, bpf_htons(dns_header->ans_count));
        #endif

        return 1;
}


static 
__always_inline __u8 parse_dns_payload_memsafet_payload(struct skb_cursor *skb, void *dns_payload) {
    // dns header already validated and payload and header memory safetyy already cosnidered 
    return 1;
} 


static 
__always_inline struct packet_actions packet_class_action(struct packet_actions actions) {
    actions.cursor_init = &cursor_init;
    actions.parse_eth = &parse_eth;
    actions.parse_ipv4 = &parse_ipv4;
    actions.parse_ipv6 = &parse_ipv6;
    actions.parse_udpv4 = &parse_udpv4;
    actions.parse_udpv6 = &parse_udpv6;
    actions.parse_dns_header_size = &parse_dns_header_size;
    actions.parse_dns_payload = &parse_dns_payload;
    actions.parse_dns_payload_memsafet_payload = &parse_dns_payload_memsafet_payload;
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
            if (actions.parse_udpv4(&cursor) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) udp + 1 > cursor.data_end) return TC_DROP;
            void * udp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            if ((void *) udp_data + 1 > cursor.data_end) return TC_DROP;

            __u32 total_offset = nhoff + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (total_offset > skb->len) return TC_DROP;
            __u32 udp_payload_len = bpf_ntohs(udp->len);
            __u32 udp_payload_exclude_header = udp_payload_len - sizeof(struct udphdr);

            if (udp_payload_exclude_header > 100) return TC_DROP;

            
            // its definitely a dns udp packet but make sure for deep scannign for mem safety
            if (udp->dest == bpf_htons(DNS_EGRESS_PORT)) {
                
                struct dns_event *event;

                event = bpf_ringbuf_reserve(&dns_ring_events, sizeof(struct dns_event), 0);
                if (!event) {
                    bpf_printk("Error in allocating ring buffer space in kernel");
                    return TC_FORWARD;
                }

                event->eventId = 10;
                event->src_ip = bpf_ntohl(ip->saddr);
                event->dst_ip = bpf_ntohl(ip->daddr);
                event->src_port = bpf_ntohs(udp->source);
                event->dst_port = bpf_ntohs(udp->dest);
                event->payload_size = (__u32)udp_payload_exclude_header;
                event->udp_frame_size = bpf_ntohs(udp->len); 
                event->dns_payload_size = bpf_htons(udp->len) - sizeof(struct udphdr)  - sizeof(struct dns_header);
                event->isUDP = (__u8) 1;
                event->isIpv4 = (__u8) 1;

                bpf_ringbuf_submit(event, 0);   

                // load the kernel buffer data into skb 
                // use output poll event to send the whole skb for dpi in kernel or use tail calls in kernel 
                #ifdef DEBUG
                    if (DEBUG) {
                        bpf_printk("A dns packet is found in the udp payload excluding header size %u", udp_payload_exclude_header);
                        bpf_printk("Submitting poll from kernel for dns udp event");
                    }
                #endif
                

                if (actions.parse_dns_header_size(&cursor, true, udp_payload_exclude_header) == 0)
                    return TC_DROP;


                void *dns_payload = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);
                if ((void *) (dns_payload + 1) > cursor.data_end) return TC_DROP;
                struct dns_header *dns = (struct dns_header *) (udp_data);

                if (actions.parse_dns_payload(&cursor, dns_payload, udp_payload_len, udp_payload_exclude_header, true, dns, skb->len) == 0) {
                    return TC_DROP;
                }

                __u16 transaction_id = (__u16) bpf_ntohs(dns->transaction_id);

                if (DEBUG) {
                    bpf_printk("[x] The transaction id Forward for the DNS Request Packet is %d ", transaction_id);
                }

                
                // update the dns query id with the check sum value prior to bpf function redirection to new ifnet interface
                __u16 *map_layer3_redirect_value;
                __u16 layer3_checksum = bpf_htons(ip->check);
                map_layer3_redirect_value = bpf_map_lookup_elem(&exfil_security_egress_redirect_map, &transaction_id);
                if (!map_layer3_redirect_value) {
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
                    return TC_FORWARD;
                    // not possible since the dnds query id are always unique 
                }
                

                // change the dest ip to point to the bridge for destination over the internal subnet of network namespaces

                __be32 current_dest_addr;
                __be32 dest_addr_route = bpf_htonl(0x0AC80001); // 10.200.0.1

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
                        return TC_ACT_OK;
                }


                if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &dest_addr_route, sizeof(dest_addr_route), 0) < 0) {
                    return TC_ACT_OK;
                }

                __u32 redirect_skb_mark = 1;
                if (skb->mark != (__u32) redirect_skb_mark) {
                    if (DEBUG) {
                        bpf_printk("Marking the packet over kernel redirection for DPI");
                    }
                    skb->mark = redirect_skb_mark;
                }
    
                #ifdef DEBUG 
                    if (!DEBUG) {
                        __u32 mod = bpf_ntohl(ip->daddr);
                        __u32 d1 = (mod >> 24) &0xFF;
                        __u32 d2 = (mod >> 16) &0xFF;
                        __u32 d3 = (mod >> 8) &0xFF;
                        __u32 d4 = mod  & 0xFF;
                        bpf_printk("current copied dest addres %u %u", d1, d2);
                        bpf_printk("current copied dest addres %u %u", d3, d4);
                    }
                #endif

                __u32 br_index = 4;
                return bpf_redirect(br_index, BPF_F_INGRESS); // redirect to the bridge
                // for now learn dns ring buff event;
            }else {

                // do deep packet inspection on the packet contetnt and the associated payload 
            }
            return TC_FORWARD;
        }else if (ip->protocol == IPPROTO_TCP) {
            if (actions.parse_tcpv4(&cursor) == 0) return TC_DROP;
            tcp = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) (tcp + 1) > cursor.data_end) return TC_DROP;

            void *tcp_data = cursor.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            if ((void *) tcp_data + 1 > cursor.data_end) return TC_DROP;

            // verify for standard or enhanced dpi inspection over the payload header 
            
            if (tcp-> dest == bpf_htons(DNS_EGRESS_PORT)) {
                // a standard port used for tcp data forwarding 
                return TC_FORWARD;
            }else {
                // need more dpi over the dns header payload format either via forwarding or payload size;
            }

            return TC_FORWARD;
        }
	}else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        if (actions.parse_ipv6(&cursor) == 0) return TC_DROP;
        ipv6 = cursor.data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > cursor.data_end) return TC_DROP;

        if (ip->protocol == IPPROTO_UDP) {
            if (actions.parse_udpv6(&cursor) == 0) return TC_DROP;
            udp = cursor.data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            return TC_FORWARD;

        }else if (ip->protocol == IPPROTO_TCP) return TC_FORWARD;
    } else return TC_FORWARD;


    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";