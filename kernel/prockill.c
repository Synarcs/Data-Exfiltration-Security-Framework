/* Copyright (c) 2024–2025 Synarcs. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * -----------------------------
 * Author: Synarcs
 * Date:   10/25/2024, 2:59:15 AM
 * ---------------------------->
*/
#include <linux/bpf.h>
#include <linux/sched.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "hdrs/consts.h"
#include "hdrs/raw_proc.h"
#include "hdrs/utils.h"
#include "hdrs/pinmaps.h"
#include "hdrs/dns.h"

struct exfill_security_ppid_fork_ct {   
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // parent process id 
    __type(value, __u32);  // number of times the process forded to spawn child process
    __uint(max_entries, 1 << 10);
} exfill_security_ppid_fork_ct SEC(".maps");

struct sched_process_fork {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char parent_comm[16];
    __u32 parent_pid;
    char child_comm[16];
    __u32 child_pid;
};

typedef struct detected_malicious_process_forks {
    __u32 ppid;
    __u32 fork_count;
};

struct exfill_security_kill_proc_tree {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} exfill_security_kill_proc_tree SEC(".maps");

static 
__always_inline struct kill_proc_mal_payload * is_process_found_malicious(__u32 proc_id) {
    struct kill_proc_mal_payload * mal_detected_proc = bpf_map_lookup_elem(&exfil_security_egress_proc_mal, &proc_id);
    if (!mal_detected_proc) return NULL;

    return mal_detected_proc;
}

static
__always_inline void is_mal_proc_below_detect_threshold_killed() {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct kill_proc_mal_payload * mal_detected_count = is_process_found_malicious(proc_id);
    if (mal_detected_count) {
        // remove if the proc was SIGTERM before reaching malicious threshold, otherwise will be SIGKILL if it exceed the malicious threshold 
        if (mal_detected_count < EGRESS_MAL_PROC_EXFIL_SCHED) {
            // 3 proc map kill free 
            if (bpf_map_delete_elem(&exfil_security_egress_proc_mal, &proc_id) < 0) {
                #if DEBUG 
                        bpf_printk("the key is removed by smp on another CPU once the process was sigkilled before thresholled reach for map clean");
                #endif
            }
            // 1 map kernel free 
            struct exfil_security_egress_nsp_map_key mal_proc_redir_key = (struct exfil_security_egress_nsp_map_key) {
                .dport = mal_detected_count->dest_port,
                .processId = proc_id,
            };
            // count of time rescan kernel redirected to user space for malicious rescan of exfil packet via clone redirect's 
            __u32 * mal_proc_redir_ct = bpf_map_lookup_elem(&exfil_security_egress_nsp_map, &mal_proc_redir_key);
            if (mal_proc_redir_ct) {
                if (bpf_map_delete_elem(&exfil_security_egress_nsp_map, &mal_proc_redir_key) < 0) {
                    #if DEBUG 
                        bpf_printk("the key is removed by smp on another CPU once the process was sigkilled before thresholled reach for map clean");
                    #endif
                }
            }
        }
    }
}

/*
    Emit ring buff events to node agent in user space to kill the malicious c2 impant  process ppid with multiple forks
*/
static 
__always_inline void __handle_parent_process_child_forks(__u32 ppid, __u32 pid) {
    __u32 * fork_ct = bpf_map_lookup_elem(&exfill_security_ppid_fork_ct, &ppid);
    if (!fork_ct) {
        if (bpf_map_update_elem(&exfill_security_ppid_fork_ct, &ppid, &pid, BPF_NOEXIST) < 0) {
            #if DEBUG
                bpf_printk("failed to update fork count for ppid %d", ppid);
            #endif 
        }
        return;
    }

    if (*fork_ct > EGRESS_DETECTED_MAP_PROC_MAX_FORK_CT) {
        struct bpf_dynptr dptr;
        struct detected_malicious_process_forks dpforks = (struct detected_malicious_process_forks) {
            .ppid = ppid,
            .fork_count = *fork_ct,
        };
        if (bpf_ringbuf_reserve_dynptr(&exfill_security_kill_proc_tree, sizeof(dpforks), 0, &dptr) < 0) {
            bpf_ringbuf_discard_dynptr(&exfill_security_kill_proc_tree, 0);
            return;
        }

        bpf_ringbuf_submit_dynptr(&dptr, 0);
        bpf_ringbuf_submit_dynptr(&exfill_security_kill_proc_tree, 0);
    }else {
        __sync_fetch_and_add(fork_ct, 1);
    }
}

// when a process sigkills itself prior to the threshold when the node agen sigkill the proc to stop further any breaches via any sock the process uses 
SEC("tracepoint/sched/sched_process_exit")
int handle_mal_c2_proc_exit() {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    #if DEBUG
        bpf_printk("running kprobe for sigkill of proc %d", proc_id);
    #endif 

    is_mal_proc_below_detect_threshold_killed();
    return 0;
}

/*
    Map the ppid from task struct as real parent id for the process to prevent the amount of forsk a malicious process can do before being sigkilled and deteted malicious over in DPI at kernel TC and userspace 
*/
SEC("tracepoint/sched/sched_process_exec")
int process_potential_mal_c2_thread_spawn()  {

  
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    pid_t ppid = 0;

    struct __kernel_proc_struct_info *proc_infp = __get_process_info();
    if (proc_infp->procId != proc_infp->threadId) {
        // a trhead spawn for the parent process in the parent task struct tgroup 
    }

    return 0;
}


SEC("tracepoint/sched/sched_process_fork")
int handle_potential_malicious_forks(struct sched_process_fork *proc_info) {
    __u32 pid = proc_info->child_pid;
    __u32 ppid = proc_info->parent_pid;

    struct kill_proc_mal_payload * is_process_mal = is_process_found_malicious(pid);
    if (!is_process_mal) {
        return 0;
    }

    __u32 * fork_count = bpf_map_lookup_elem(&exfill_security_ppid_fork_ct, &ppid);
    if (!fork_count) return 0;

    __sync_fetch_and_add(fork_count, 1);
    return 0;
}



char __license[] SEC("license") = "Dual MIT/GPL";
