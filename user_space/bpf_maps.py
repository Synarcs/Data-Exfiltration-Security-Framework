import os

from bcc import BPF
from concurrent.futures import  ProcessPoolExecutor as exec, ThreadPoolExecutor as thread
from datetime import  datetime
from collections import OrderedDict as LinkedHashMap
import socket as sc

# BPF_HASH(output)  // defines a hash map for bpf to be used in user space

prog = r"""
    BPF_PERF_OUTPUT(output);
    BPF_HASH(HASH_TABLE_MAP);
    struct data_t {
         int pid;
         int uid;
         char command[16];
         char message[16];
    };
    int hello(void *ctx) {
         struct data_t data = {};
         char message[16] = "Hello there";
         data.pid = bpf_get_current_pid_tgid() >> 32;
         data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        
         if (data.pid % 2 != 0){}
                 
         bpf_get_current_comm(&data.command, sizeof(data.command));
         bpf_probe_read_kernel(&data.message, sizeof(data.message), message); //  copies it into the right place in the data structure.
         output.perf_submit(ctx, &data, sizeof(data));
         return 0;
    }
"""

class PerfEvent:
    pid: int; uid: int; command: str; message: str

fopen = '''
    int fOpen(void *ctx){
        bpf_trace_printk("file open Hnalder triggered");
        return 0;
    }
'''

def compile(codeName: str):
    bpf = BPF(text=codeName)
    return  bpf

def handler(poolId: int):
    bpf = compile(codeName=prog)
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("mmap"), fn_name="hello")
    print('running tracer pool for process ', os.getpid())
    with thread(max_workers=2) as tPool:
        future = tPool.submit(fn=lambda: print(datetime.now()))
        if future.done():
            print(future.result())

def buffer_ring_handler():
    '''
        Poll the ring buffer flushed via kernel space to user space inside the buffer maps
        each map received on basisc of a single cpu order map
    :return:
    '''

    bpf = BPF(text=prog)
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("mmap"), fn_name="hello")

    bpf.get_table("sample").open_perf_buffer(lambda xx: print(xx))
    def print_event(cpu, data: PerfEvent, size):
        data = bpf.get_table('output').event()
        print(f"Cpu Used for Map: {cpu} {data.pid} {data.uid} {data.command.decode()} " + \
              f"{data.message.decode()}")

    bpf.get_table("output").open_perf_buffer(print_event)
    # for k,v in bpf['hash_map'].items(): print('polling the kernel space from user space')
    while True:
        bpf.perf_buffer_poll()

# if __name__ == "__main__":
#     bpf = compile(fopen)
#     bpf.attach_kprobe(event=bpf.get_syscall_fnname("openat"), fn_name="fOpen")
#     bpf.trace_print()
#
#
