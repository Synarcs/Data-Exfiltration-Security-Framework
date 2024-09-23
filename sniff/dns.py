from scapy.all import DNS, DNSRR, IP, sr1, UDP, DNSQR, IPv6 
from scapy.all import ICMP, send
import os, random

domains = ["google.com", "apple.com", "intel.com"]
custom_id = random.randint(1, 1 << 10)
dns = DNS(id=custom_id,rd=1, qd=DNSQR(qname=random.choice(domains)))

#dns.qr = DNSQR(qname=random.choice(domains))

#dns.an = DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300) /  DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300)


dns_req = IP(dst='192.168.64.1') / UDP(dport=53) / dns

dns_req.show()

print(os.getpid())


# sent the packet directly over the bridge interface
if __name__ == "__main__":
    send(dns_req, verbose=True, iface="enp0s1")
