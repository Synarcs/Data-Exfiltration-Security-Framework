from scapy.all import *

domains = ["kv801.prod.do.dsp.mp.microsoft.com", "google.com", "apple.com", "intel.com"]

dns_server:str = "10.158.82.55"
iface: str  = "enp0s1" 

src_port = RandShort()
dst_port = 53 

syn = IP(dst=dns_server) / TCP(sport=src_port, dport=dst_port, flags="S")
syn_ack = sr1(syn, iface=iface, timeout=2, verbose=True)

if not syn_ack:
    print("No SYN-ACK received, connection failed.")
    exit()

ack = IP(dst=dns_server) / TCP(sport=src_port, dport=dst_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
send(ack, iface=iface, verbose=False)

dns_query = (IP(dst=dns_server) /
             TCP(sport=src_port, dport=dst_port, flags="PA", seq=syn_ack.ack, ack=syn_ack.seq + 1) /
             DNS(rd=1, qd=DNSQR(qname=domains[-3], qtype="A")))

# print(dns_query.show())

response = sr1(dns_query, iface=iface, timeout=3, verbose=True)

if response and response.haslayer(DNS):
    print("Received DNS Response:")
    print(response.show())
else:
    print("No DNS response received.")