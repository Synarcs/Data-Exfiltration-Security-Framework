#include <linux/bpf.h>

#include <sys/socket.h>
#include <linux/netlink.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "consts.h"
#include "dns.h"


// monitor all netlink events from kernel for AF_NETLINK 
struct exfil_security_detected_c2c_tunneling_netlink_sock_event {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} exfil_security_detected_c2c_tunneling_netlink_sock_event SEC(".maps");

struct event_setSockEvent {
    __u32 process_id;
    __u32 uid;
    char prog[200];
};

struct socket_args {
    unsigned long  pad;
    unsigned int __syscall_nr;
    unsigned int family;
    unsigned int type;
    unsigned int protocol;
};

SEC("tracepoint/syscalls/sys_enter_socket")
int netlink_socket(struct socket_args *ctx) {

    if (ctx->type == AF_NETLINK) {

        void *res = bpf_ringbuf_reserve(&exfil_security_detected_c2c_tunneling_netlink_sock_event, 
                        sizeof(struct event_setSockEvent), 0);
        if (!res) {
            #ifdef DEBUG
                if (DEBUG) {
                    bpf_printk("socket info %u %u %u", ctx->family, ctx->type, ctx->protocol);
                }
            #endif
            // bpf_ringbuf_discard(&exfil_security_detected_c2c_tunneling_netlink_sock_event, 0);
            return 0;
        }
        struct event_setSockEvent *event = res;

        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u32 uid = bpf_get_current_uid_gid() >> 32;

        if (
            bpf_get_current_comm(&event->prog, sizeof(event->prog)) == 0
        ) {
            if (DEBUG)
                bpf_printk("netlink socket detected %s", event->prog);
        }

        event->process_id = pid; 
        event->uid = uid;

        bpf_ringbuf_submit(event,0);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";