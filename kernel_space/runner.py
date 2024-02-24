

#!/usr/bin/python3
import os, multiprocessing as mp, time
from concurrent.futures import ProcessPoolExecutor as pool
import netifaces as nif
from bcc import  BPF
from queue import Queue


class EbpfAgent(object):
    egressQueue:Queue = Queue()
    ingressQueue:Queue = Queue()
    bpf: BPF = None

    def __init__(self):
        super()
        b = BPF(src_file="main.c")
        self.bpf = b

    def attach_xdp(self, interface: str):
        print(f'Bpf interface handled by process interface {interface} and {os.getpid()}')
        # XDP will be the first program hit when a packet is received ingress before the nwtwork route
        BPF.attach_xdp(interface, self.bpf.load_func("xdp", BPF.XDP), 0)

    def loadIngress(self):
        interfaces= nif.interfaces()
        with pool(max_workers=mp.cpu_count()) as bpfQueue:
            bpfQueue.map(self.attach_xdp, interfaces)

    def listenIcmpevents(self):
        def print_event(cpu,data, size):
            # not useful for ring buffer case
            data = self.bpf.get_table("perf_output").event(data)
            print(data)

        self.bpf.get_table('perf_output').open_perf_buffer(print_event)
        while True:
            time.sleep(2)
            self.bpf.perf_buffer_poll()
        # kernel polling
        # while True:
        #     time.sleep(2) # polling the kernel map to kernel space from user space
        #     for k, v in self.bpf.get_table("icmp_contrack").items():
        #         print(f"the dvalue is {k.value} and value is {v.value}")

if __name__ == "__main__":
    agent = EbpfAgent()
    agent.loadIngress()
    agent.listenIcmpevents()

