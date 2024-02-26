#include "xdp_helper.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <linux/icmp.h>
#include <linux/types.h>

//only for debugging purpose to debuf strace
//#include <bpf/bpf_helpers.h>

BPF_HASH(icmp_contrack, u64, u64 );
BPF_PERF_OUTPUT(perf_output); // a per output for now later a ring buffer

struct icmp_event {
    u64 time_data;
    int icmp_count;
};

int xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct icmphdr *icmp = is_icmp_layer3(data, data_end);
    struct tcphdr *tcp = is_tcp_header(data, data_end);
    struct icmp_event event = {};
    if (icmp){
        bpf_trace_printk("Got ping packet");
        u64 time;
        time = bpf_ktime_get_ns();

        u64 packet_time_count = 1;

        event.time_data = time;
        event.icmp_count = packet_time_count;

        u64 *pres;
        pres = icmp_contrack.lookup(&time);
        if (!pres){
            icmp_contrack.update(&time,  &packet_time_count);
        }
        perf_output.perf_submit(ctx, &event, sizeof (struct icmp_event));

        return XDP_DROP;
    }else if (tcp != NULL){
        bpf_trace_printk("Got ping packet");
    }

    return XDP_PASS;
}