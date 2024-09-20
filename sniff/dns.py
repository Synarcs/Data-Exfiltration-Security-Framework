from scapy.all import DNS, DNSRR, IP, sr1, UDP
from scapy.all import ICMP, send
import os, random

dns = DNS(id=random.randint(1, 1 << 16), rd=1)
domains = ["google.com", "apple.com", "intel.com"]

dns.an = DNSRR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300) /  DNSRR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300)


dns_req = IP(dst='8.8.8.8') / UDP(dport=53) / dns

dns_req.show()

print(os.getpid())


if __name__ == "__main__":
    send(dns_req, verbose=True, iface="enp0s1")
