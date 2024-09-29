from scapy.all import DNS, DNSRR, IP, sr1, UDP, DNSQR, IPv6 
from scapy.all import ICMP, send
import os, random
from pathlib import Path
 

domains = ["google.com", "apple.com", "intel.com"]
dns = DNS(id=100,rd=1, opcode=2)

dns.qd = DNSQR(qname="intel.com") / DNSQR(qname="apple.com") 
# dns.an = DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300) /  DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300)

dns_req = IP(dst='192.168.64.1') / UDP(dport=53) / dns

dns_req.show()

print(os.getpid())


# sent the packet directly over the bridge interface
if __name__ == "__main__":
    send(dns_req, verbose=True, iface="enp0s1")
