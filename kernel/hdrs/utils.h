/* 
    Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/
#ifndef __UTILS_H_ 
    #define __UTILS_H_ 

#include <stdbool.h>
#include <linux/kernel.h>
#include <linux/version.h>


#define max(_x, _y) __builtin_types_compatible_p(typeof((_x)), typeof((_y))) ? ((_x) > (_y) ? (_x) : (_y)) : (_x) 
#define min(_x, _y) __builtin_types_compatible_p(typeof((_x)), typeof((_y))) ? ((_x) > (_y) ? (_y) : (_x)) : (_x)

#define isUpper(a) ((a) - 'A' >= 0 && 'Z' - (a) >= 0)
#define isLower(a) ((a) - 'a' >= 0 && 'z' - (a) >= 0)
#define isDigit(a) ((a) - '0' >= 0 && '9' - (a) >= 0)

#define forn(x, i) for (typeof(i) i = 0; i < (x); i++)
#define forin(x, y, i) for (typeof(i) i = (x); i < (y); i++)

// cursor to and other encap protocol information storing packet cursor information in skb 
struct skb_cursor {
    void *data;
    void *data_end;
} __attribute__((packed));

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
} __attribute__((packed));

struct __kernel_proc_struct_info {
    __u32 procId;
    __u32 threadId;
} __attribute__((packed));

struct __kernel_uid_struct_info {
    __u32 userId;
    __u32 groupId;
} __attribute__((packed));


/*
    Verify does kernel support task_comm for task struct specifically for kernel traffic control
*/
static 
__always_inline bool verify_kernel_version_support_task_comm() {
    return LINUX_VERSION_MAJOR >= TC_TASK_LINUX_MAJOR_RELEASE_SUPPORT && 
            (LINUX_VERSION_SUBLEVEL >= TC_TASK_LINUX_SUBRELEASE_SUPPORT || LINUX_VERSION_PATCHLEVEL >= TC_TASK_LINUX_SUBRELEASE_SUPPORT);
}


#define VERIFY_TCX_SUPPORT LINUX_VERSION_MAJOR >= TCX_LINUX_MAJOR_RELEASE_SUPPORT && LINUX_VERSION_SUBLEVEL >= TCX_LINUX_SUBRELEASE_SUPPORT

/*
    Rely on kernel task comm for the tc running on whichever CPU handles and retrieve the process name and associated task struct
*/
static 
__always_inline struct __kernel_proc_struct_info * __get_process_info(bool is_non_tc ) {
    struct __kernel_proc_struct_info proc_info;
    
    // the kernel bpf helper internally calling kernel trask struct is always exposed to the non kernel TC layer. 
    if (verify_kernel_version_support_task_comm() || is_non_tc) {
        __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
        __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        proc_info.procId = proc_id;
        proc_info.threadId = thread_id;
    }else {
        proc_info.procId = 0;
        proc_info.threadId = 0;
    }
    return &proc_info;
}


/*
    Rely on kernel task comm for the tc running on whichever CPU handles and retrieve the process name and associated task struct
*/
static 
__always_inline struct __kernel_uid_struct_info * __get_uid_info() {
    struct __kernel_uid_struct_info proc_info;

    // TODO: Fix the version and match the kernel patch level  
    if (verify_kernel_version_support_task_comm()) {
        __u32 proc_id = bpf_get_current_uid_gid() >> 32;
        __u32 thread_id = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        proc_info.userId = proc_id;
        proc_info.groupId = thread_id;
    }else {
        proc_info.userId = 0;
        proc_info.groupId = 0;
    }
    return &proc_info;
}

static
__always_inline bool __has_skb_mark(struct __sk_buff *skb) {
    return skb->mark > 0;
}

#endif 
