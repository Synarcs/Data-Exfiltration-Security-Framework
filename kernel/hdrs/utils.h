#ifndef __UTILS_H_ 
#define __UTILS_H_ 

#include <stdbool.h>
#include <linux/version.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))



#define isUpper(a) ((a) - 'A' >= 0 && 'Z' - (a) >= 0)
#define isLower(a) ((a) - 'a' >= 0 && 'z' - (a) >= 0)
#define isDigit(a) ((a) - '0' >= 0 && '9' - (a) >= 0)



#define div(a, b) ((a) / (b))


#define forn_unroll(x,type , ...) _Pragma(unroll (x)) for (type i=0; i < x; i++)

#define fork_unroll(x, y , type, ...) _Pragma (unroll(x)) for (type i=x; i <= y; i++)


#define __print_type(a, ...) __GENERIC(x, \
    __u8: bpf_printk("%u\n", a) \
    default: bpf_printk("Generic type not processed\n") \
)

#define __GENERIC_PRINT(x, ...) __GENERIC_TYPE(x, __VA_ARGS__) 


#define CHECK_BOUNDS(ptr, offset, end, ct) \
    if ((void *)((ptr) + (offset) + 1) > (end)) \
        return (ct);

#define CHECK_BOUNDS_OFFSET(ptr, offset, end, ct)  \
    if ((void *)((ptr) + (offset)) > (end)) \
        return (ct);



struct __kernel_proc_struct_info {
    __u32 procId;
    __u32 threadId;
} __attribute__((packed));

struct __kernel_uid_struct_info {
    __u32 userId;
    __u32 groupId;
} __attribute__((packed));


/*
    Verify does kernel support task_comm for task struct 
*/
static 
__always_inline bool verify_kernel_version_support_task_comm() {
    if (LINUX_VERSION_MAJOR >= LINUX_MAJOR_RELEASE_SUPPORT && LINUX_VERSION_SUBLEVEL >= LINUX_SUBRELEASE_SUPPORT) {
        if (LINUX_VERSION_MAJOR == LINUX_MAJOR_RELEASE_SUPPORT && LINUX_VERSION_SUBLEVEL == LINUX_SUBRELEASE_SUPPORT)
            return LINUX_VERSION_PATCHLEVEL >= 0;
        return true;
    }
    return false;
}

/*
    Rely on kernel task comm for the tc running on whichever CPU handles and retrieve the process name and associated task struct
*/
static 
__always_inline struct __kernel_proc_struct_info * __get_process_info() {
    struct __kernel_proc_struct_info proc_info;

    if (verify_kernel_version_support_task_comm()) {
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


#endif 