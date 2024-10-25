from scapy.all import DNS, DNSRR, IP, sr1, UDP, DNSQR, IPv6
from scapy.all import ICMP, send
import os

domains = ["kv801.prod.do.dsp.mp.microsoft.com","google.com", "apple.com", "intel.com"]
dns = DNS(
    id=100,
    rd=1,  
)

dns.qd = DNSQR(qname=domains[0])

dns_req = (
    IPv6(dst='fe80::cc08:faff:fe26:a064', hlim=64)/ 
    UDP(dport=53)/ 
    dns
)

dns_req.show()

print(os.getpid())

if __name__ == "__main__":
    ans = sr1(dns_req, iface="enp0s1", timeout=2, verbose=True)
    if ans:
        ans.show()
