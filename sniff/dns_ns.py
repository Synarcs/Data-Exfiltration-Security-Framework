from scapy.all import DNS, DNSRR, IP, sr1, UDP, DNSQR
from scapy.all import ICMP, send
import os, random

# send a packet from net ns to the host bridge

dns = DNS(rd=1, qd=DNSQR(qname='intel.com'))
domains = ["google.com", "apple.com", "intel.com"]

#dns.qr = DNSQR(qname=random.choice(domains))

#dns.an = DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300) /  DNSQR(rrname=random.choice(domains), rdata="93.184.216.34", ttl=300)


dns_req = IP(src="192.168.64.23",dst='192.168.64.1') / UDP(dport=53) / dns

dns_req.show()

print(os.getpid())


if __name__ == "__main__":
    send(dns_req, verbose=True, iface="lo")
