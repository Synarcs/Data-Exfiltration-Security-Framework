#!/bin/python3

from bcc import BPF
import torch
import torch.nn as nn
from torch.func import  hessian
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from scapy.all import *
import asyncio


class BpfMapPoller():
    def __init__(self): pass


if __name__ == "__main__":
    try:
        interface: str = 'docker0'
        b = BPF(src_file="xdp.c")
        b.attach_xdp(interface, b.load_func("handler", BPF.XDP), 0)
        for k,v in b.get_table("dnsBuffer").items():
            print("the key and value is ", k, v)

    except KeyboardInterrupt as err:
        b.trace_print()
    except Exception as err:
        print(err)

