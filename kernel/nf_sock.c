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
    __uint(max_entries, 1 << 10);
} exfil_security_detected_c2c_tunneling_netlink_sock_event SEC(".maos");

struct event_setSockEvent {
    char processInfo[255];
    __u32 process_id;
    __u32 uid;
};

struct socket_args {
    __u64 pad;
    __s32 domain;
    __s32 type;
    __s32 protocol;
};

SEC("tracepoint/syscalls/sys_enter_socket")
int netlink_socket(struct socket_args *ctx) {


    if (ctx->domain == AF_NETLINK && ctx->type == (SOCK_RAW | SOCK_CLOEXEC) &&
            ctx->protocol == NETLINK_ROUTE) {

        #ifdef DEBUG
            if (DEBUG) {

            }
        #endif
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u32 uid = bpf_get_current_uid_gid() >> 32;
        
        struct event_setSockEvent *event;
        event->process_id = pid; 
        event->uid = uid;

        bpf_get_current_comm(event->processInfo, sizeof(event->processInfo));

        bpf_ringbuf_output(&exfil_security_detected_c2c_tunneling_netlink_sock_event, 
                    event, sizeof(struct event_setSockEvent), 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";