
# !/usr/bin/python3
import os, multiprocessing as mp, time
from concurrent.futures import ProcessPoolExecutor as pool
import netifaces as nif
from bcc import  BPF
from queue import Queue
import logging, signal
from typing import List
from pyroute2 import IPRoute

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class NetInterfaces(object):

    def __init__(self): super()
    def get_interfaces(self) -> List:
        return nif.interfaces()


class EbpfTCAgent(NetInterfaces):
    netlink: IPRoute = IPRoute()
    bpf: BPF
    def __init__(self):
        super().__init__()
        self.bpf = BPF(src_file='egress.c')
    def handletracerouteRule(self, interface):
        id =  self.netlink.link_lookup(interface)[0]
        self.netlink.tc("add", "egress", id, "ffff:")
        self.netlink.tc("add-filter", "bpf", id, ":1",
                            fd= self.bpf.load_func("egress_handler", BPF.SCHED_CLS))

    def attachTc(self):
        interfaces = self.get_interfaces()
        with pool(max_workers=mp.cpu_count()) as processPool:
            processPool.map()


class EbpfXDPAgent(NetInterfaces):
    egressQueue :Queue = Queue()
    ingressQueue :Queue = Queue()
    bpf: BPF = None

    def __init__(self):
        super().__init__()
        b = BPF(src_file="main.c")
        self.bpf = b

    def attach_xdp(self, interface: str):
        print(f'XDP BPF interface handled by process interface {interface} and {os.getpid()}')
        # XDP will be the first program hit when a packet is received ingress before the nwtwork route
        BPF.attach_xdp(interface, self.bpf.load_func("xdp", BPF.XDP), 0)

    def loadIngress(self):
        interfaces = self.get_interfaces()
        with pool(max_workers=mp.cpu_count()) as bpfQueue:
            bpfQueue.map(self.attach_xdp, interfaces)

    def listenIcmpevents(self):
        def print_event(cpu ,data, size):
            # not useful for ring buffer case
            data = self.bpf.get_table("perf_output").event(data)
            print('invoked called')
            print(data)

        self.bpf.get_table('perf_output').open_perf_buffer(print_event)
        while True:
            self.bpf.perf_buffer_poll()
        # kernel polling
        # while True:
        #     time.sleep(2) # polling the kernel map to kernel space from user space
        #     for k, v in self.bpf.get_table("icmp_contrack").items():
        #         print(f"the dvalue is {k.value} and value is {v.value}")

parent_process: int = None

"""
    signum:  SIGINT --> Process with Parent process as 1
"""
def handleProcessInterrupt(signum: int, frame: object) -> None:
    global parent_process
    parent_process = os.getpid()
    if parent_process != os.getppid():
        print(frame)
        logger.error("Error Fuck cannot kilel an orphan process")
        raise Exception("Error cannot kill the process in Root context")
    else: exit(1)

def handleKiller(signnum: int , frame: object) -> None: exit(1)

if __name__ == "__main__":
    parent_proces = os.getppid()
    child_process = os.getpid()

    user_space_interrupt = signal.signal(signal.SIGINT, handleProcessInterrupt)
    # user_space_kill = signal.signal(signal.SIGKILL, handleKiller)

    agent = EbpfXDPAgent()
    agent.loadIngress()
    agent.listenIcmpevents()
