from scapy.all import DNS, DNSRR, IP, sr1, UDP, DNSQR, IPv6 
from scapy.all import ICMP, send
import os, random

custom_id = random.randint(1, 1 << 10)
dns = DNS(id=1223,rd=1, qd=DNSQR(qname='intel.com'))
domains = ["google.com", "apple.com", "intel.com"]

#dns.qr = DNSQR(qname=random.choice(domains))

#dns.an = DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300) /  DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300)


dns_req = IP(dst='10.200.0.2') / UDP(dport=53) / dns

dns_req.show()

print(os.getpid())


# sent the packet directly over the bridge interface
if __name__ == "__main__":
    send(dns_req, verbose=True, iface="enp0s1")
