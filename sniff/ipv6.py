from os import path 
import sys 
from scapy.all import *;

ip = IPv6()
i.dst="2001:db8:dead::1"
q=ICMPv6EchoRequest()
p=(i/q)
sr1(p)

if __name__ == "__main__": pass 
