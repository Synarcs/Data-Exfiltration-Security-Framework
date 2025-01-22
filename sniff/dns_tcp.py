from scapy.all import *


domains = ["kv801.prod.do.dsp.mp.microsoft.com","google.com", "apple.com", "intel.com"]

dns_query = (IP(dst='192.168.64.1') /
            TCP(sport=RandShort(), dport=53)/
            DNS(rd=1,
                qd=DNSQR(qname=domains[-2], qtype="A")))

print(dns_query.show())
response = sr1(dns_query, iface="enp0s1", timeout=2, verbose=True)

if response: print(response) 
