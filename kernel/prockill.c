// <!---------------------------
// Name: DNSObelisk
// File: prockill.c
// -----------------------------
// Author: Synarcs
// ---------------------------->

#include <linux/bpf.h>
#include <linux/sched.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "consts.h"
#include "raw_proc.h"
#include "utils.h"
#include "pinmaps.h"
#include "dns.h"


static
__always_inline void is_mal_proc_below_detect_threshold_killed() {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    
    struct kill_proc_mal_payload * mal_detected_count = bpf_map_lookup_elem(&exfil_security_egress_proc_mal, &proc_id);
    if (mal_detected_count) {
        // remove if the proc was SIGTERM before reaching malicious threshold, otherwise will be SIGKILL if it exceed the malicious threshold 
        if (mal_detected_count < EGRESS_MAL_PROC_EXFIL_SCHED) {
            // 3 proc map kill free 
            if (bpf_map_delete_elem(&exfil_security_egress_proc_mal, &proc_id) < 0) {
                #ifdef DEBUG 
                    if (!DEBUG) 
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
                    #ifdef DEBUG 
                        if (DEBUG) 
                            bpf_printk("the key is removed by smp on another CPU once the process was sigkilled before thresholled reach for map clean");
                    #endif
                }
            }
        }
    }
}

// when a process sigkills itself prior to the threshold when the node agen sigkill the proc to stop further any breaches via any sock the process uses 
SEC("tracepoint/sched/sched_process_exit")
int handle_mal_c2_proc_exit() {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    #ifdef DEBUG
        if (DEBUG)
            bpf_printk("running kprobe for sigkill of proc %d", proc_id);
    #endif 

    is_mal_proc_below_detect_threshold_killed();
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
