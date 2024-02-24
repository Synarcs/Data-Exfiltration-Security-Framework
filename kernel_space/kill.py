
import os , sys
from bcc import  BPF
import netifaces as nif


b = BPF(src_file="main.c")
interfaces= nif.interfaces()

for interface in interfaces:
    b.remove_xdp(interface, 0)
