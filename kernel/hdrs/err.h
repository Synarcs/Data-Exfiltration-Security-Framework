/* 
    Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

#ifndef _ERR_H_
#define _ERR_H_ 

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "consts.h"
#include <string.h>

// 64 char error pipe per ring buff event
#define KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE 1 << 7

struct exfil_sec_error {
    char err[KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE];
} __attribute__((packed));

struct exfil_security_error_pipe_agent {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_error_pipe_agent SEC(".maps");

static
__always_inline int __get_len(char *msg) {
    int len = 0;
    #pragma unroll
    for (int i=0; i < KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE; i++) {
        if (msg[i] == '\0') break;
        len++;
        if (len > KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE) return KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE;
    }
    return len;
}

// this is kernle enforced endpoint security advanced kernel security enforcement must not ramp up the sys fs trace pipe, rather export metrics to agent in userspace for proper monitoring of kernel error fail events across datapath and other security and tracepoints layers
static 
__always_inline int __emit_error_msg_ringbuff(char * err_message) {
    int len = __get_len(err_message);

    //verifier check large error message all cannot be put enitrely on stack 
    struct exfil_sec_error err_message_payload = {};
    __builtin_memcpy(&err_message_payload.err, err_message, sizeof(char) * len);
    
    struct bpf_dynptr dptr_err;
    if (bpf_ringbuf_reserve_dynptr(&exfil_security_error_pipe_agent,
                                   sizeof(struct exfil_sec_error), 0, &dptr_err) < 0) {
        return -1;
    }

    bpf_dynptr_write(&dptr_err, 0, &err_message_payload, sizeof(struct exfil_sec_error), 0);
    bpf_ringbuf_submit_dynptr(&dptr_err, 0);
    return 0;
}

#endif /* _ERR_H_ */