#include <linux/udp.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/types.h>
#include <linux/socket.h>

#include <stdbool.h>

// libbpf 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include "consts.h"
#include "utils.h"
#include "sockpin.h"

static 
__always_inline void __process_udp_sock_mp_update(struct bpf_sock_ops *sock_opt){
    void *data = (void *)(long)sock_opt->skb_data;
    void *data_end = (void *)(long)sock_opt->skb_data_end;

    struct __kernel_proc_struct_info * kernel_proc_info = __get_process_info();
    struct __kernel_uid_struct_info * kernel_user_info = __get_uid_info();

    struct udp_sock_conn_info udp_conn_sock = (struct udp_sock_conn_info) {
        .groupId = kernel_user_info->groupId,
        .userId = kernel_user_info->userId,
        .pid = kernel_proc_info->procId,
        .threadId = kernel_proc_info->threadId,
    };

    __u16 src_transfer_port = bpf_ntohs(sock_opt->local_port);

    struct udp_sock_conn_info *curr_info = bpf_map_lookup_elem(&exfil_sock_udp_conn_map, &src_transfer_port);
    if (!curr_info) {
        bpf_map_update_elem(&exfil_sock_udp_conn_map, &src_transfer_port, &udp_conn_sock, BPF_NOEXIST);
    }else {
        bpf_map_update_elem(&exfil_sock_udp_conn_map, &src_transfer_port, &udp_conn_sock, BPF_ANY);
    }
}

SEC("sockops")
int dns_sock_ops(struct bpf_sock_ops *skops) {
    
    if (verify_kernel_version_support_task_comm()) 
        goto SKIP_TASK_COMM_SKB_UPDATE_SOCK_LAYER;


    __process_udp_sock_mp_update(skops);

    SKIP_TASK_COMM_SKB_UPDATE_SOCK_LAYER:
    return SK_PASS;
}


