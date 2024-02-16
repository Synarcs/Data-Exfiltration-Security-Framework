from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sched.h>
#include <uapi/linux/kernel.h>
#include <uapi/linux/ip.h>

int tracepoint_handler(struct pt_regs *ctx) {
    struct iphdr header;
    bpf_probe_read_kernel(&header, sizeof(struct iphdr), (void *)PT_REGS_RC(ctx));

    bpf_trace_printk("Raw Tracepoint Data: %llx %d\\n", PT_REGS_RC(ctx) , sizeof(header));
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="tracepoint_handler")
b.trace_print()