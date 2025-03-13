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


static
__always_inline void is_mal_proc_below_detect_threshold_killed() {
    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    
    __u32 * mal_detected_count = bpf_map_lookup_elem(&exfil_security_egress_proc_mal, &proc_id);
    if (mal_detected_count) {
       if (mal_detected_count <= EGRESS_MAL_PROC_EXFIL_SCHED) {
          bpf_map_delete_elem(&exfil_security_egress_proc_mal, &proc_id);       
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
