#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct dns_tc_event{
    int * (*buffer) (struct dns_tc_event *node);
    struct dns_tc_event * (* event_node) (void * size, int * (*fn) (int *));
};

#define SIZE_INFO(ptr, data, end) \ 
    if ((void *) ptr + sizeof(data) > end) return TC_ACT_SHOT;
#define PRINT_DEBUG(fmt, ...) bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__)
#define PRINT_DEBUG(...) bpf_trace_printk(__VAR__ARGS);
#define ull unsigned long long 
#define ll long 

struct ring_event {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} dns_events SEC(".maps");

struct payload_data {
  __u32 len;
  __u8 data[1500]; // Max Ethernet frame size
};

struct kernel_handler_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u8);
    __type(value, __u16);
} maps SEC(".maps");


SEC("filter")
int classify(struct __sk_buff *skb){
    
    void *data_end = (void *) (ull *) (skb->data_end);
    void *data = (void *) (ull *) (skb->data);
    
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof (struct ethhdr) > data_end) return TC_ACT_SHOT;

    struct iphdr *iphdr = data + sizeof(struct ethhdr);

    if ((void *)iphdr + sizeof(struct iphdr) > data_end) return TC_ACT_SHOT;

    __u32 saddr = bpf_ntohs(iphdr->saddr); 
    __u8 s1 = (saddr >> 24) & 0xFF;  // First octet
    __u8 s2 = (saddr >> 16) & 0xFF;  // Second octet
    __u8 s3 = (saddr >> 8) & 0xFF;   // Third octet
    __u8 s4 = saddr & 0xFF;          // Fourth octet
    

    switch(iphdr->protocol) {
        case IPPROTO_ICMP: {
            __u8 ttl_icmp = iphdr->ttl;
            bpf_printk("the icmp packet found %u", ttl_icmp);
            bpf_printk("Address is %u.%u", s1, s2);
            bpf_printk("Address is %u.%u", s3, s4);
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *) udp + sizeof(struct udphdr) > data_end) return TC_ACT_OK;
            __u16 src_port = bpf_ntohs(udp -> source);
            __u8 dest_port = bpf_ntohs(udp -> dest);

            #pragma unroll(1)
            for (int i=1; i <= 1; i++) bpf_printk("src and dest port are %u %u", src_port, dest_port);

            //  pass the single ring buff to user space 
            // void *ring_buff_store = bpf_ringbuf_reserve(&dns_events, udp->len - sizeof(struct udphdr), BPF_ANY);

            __u16 udp_len = bpf_ntohs(udp->len);
            __u16 udp_len_payload = udp_len - sizeof(struct udphdr);

            void *udp_data = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            if (udp_data > data_end) return TC_ACT_OK;
            if (udp_data + udp_len_payload > data_end) return TC_ACT_OK;


            if (bpf_map_update_elem(&maps, (void *) &dest_port, (void *) &udp_len_payload, BPF_ANY) < 0){
                bpf_printk("Error Update the base map");
                return TC_ACT_OK;
            }
            // struct payload_data *pd;

            // pd = bpf_ringbuf_reserve(&dns_events, sizeof(struct payload_data), BPF_ANY);
            // if (!pd) {
            //     bpf_printk("The Kernel Size exceed capacity for ring buffer reserve");
            //     return TC_ACT_OK;
            // }

            // pd->len = udp_len_payload;

            // if (bpf_skb_load_bytes(skb, udp_data - data, pd->data, udp_len_payload) < 0){
            //     bpf_ringbuf_discard(pd, 0);
            // }

        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";

