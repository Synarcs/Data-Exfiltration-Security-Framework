#include <linux/bpf.h>
#include <linux/fs.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <signal.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "consts.h"
#include "dns.h"


// monitor all netlink events from kernel for AF_NETLINK 
struct exfil_security_detected_c2c_tunneling_netlink_sock_event {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} exfil_security_detected_c2c_tunneling_netlink_sock_event SEC(".maps");

#ifndef MAX_PROC_COMM_SIZE
    #define MAX_PROC_COMM_SIZE 200 
#endif 

struct event_setSockEvent {
    __u32 process_id;
    __u32 uid;
    __u32 gid;
    __u32 tgid;
    char prog[MAX_PROC_COMM_SIZE];
} __attribute__((packed));

struct socket_args {
    unsigned long  pad;
    unsigned int __syscall_nr;
    unsigned int family;
    unsigned int type;
    unsigned int protocol;
} __attribute__((packed));;

// replace raw af_netlink socket with custom tun/tap ioctl fd tracking in the kernel 
// tracepoint/syscalls/sys_enter_socket
SEC("kprobe/tun_chr_open")
int netlink_socket() {

    struct bpf_dynptr dptr;
    if (bpf_ringbuf_reserve_dynptr(&exfil_security_detected_c2c_tunneling_netlink_sock_event, sizeof(struct event_setSockEvent), 0, &dptr) < 0){
        if (DEBUG) {
            bpf_printk("Error allocating memory for dynamic ptr size in ring buffer");
        }
        bpf_ringbuf_discard_dynptr(&dptr, 0);
        return 0;
    }
    struct event_setSockEvent event = (struct event_setSockEvent) {
        .process_id = bpf_get_current_pid_tgid() >> 32, 
        .tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF,
        .uid = bpf_get_current_uid_gid() >> 32,
        .gid = bpf_get_current_uid_gid() & 0xFFFFFFFF, 
    };
    if (
        bpf_get_current_comm(&event.prog, sizeof(event.prog)) == 0
    ) {
        if (DEBUG)
            bpf_printk("netlink socket detected %s", event.prog);
    }
    long res = bpf_dynptr_write(&dptr, 0, &event, sizeof(struct event_setSockEvent), 0);
    bpf_ringbuf_submit_dynptr(&dptr, 0);

    // bpf_send_signal(SIGKILL);
    return 0;
}


char __license[] SEC("license") = "Dual MIT/GPL";