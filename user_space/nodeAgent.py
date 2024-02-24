from concurrent.futures import ProcessPoolExecutor as pool
from concurrent.futures import ThreadPoolExecutor as threadPool
import netifaces, sys, multiprocessing as mp, os
from scapy.all import *
from enum import Enum 
from typing import List
import logging, grpc


class EGRESS(Enum):
    EGRESS_BENIGN = 1,
    EGRESS_MALICIOUS = 2


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) 


def isIpv4(add: str) -> bool: return True if len(add.split('.')) == 4 else False
def isIpv6(add: str) -> bool: return True if len(add.split(':')) == 6 else False


class Agent(object):
    interfaces:List = []
    DNS_PORT: int = 53 

    def __init__(self) -> None:
        super()
        self.getinterfaces()

    def getinterfaces(self):
        self.interfaces = netifaces.interfaces()

    
    def listen_raw_socket(self, interface):
         print('listening to the present raw IF_INET socket in user-sapce', os.getpid(), interface)
         sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) 
         sock.bind((interface, 0))

         def dns_threadHandler(dns_packet):
             egress.add(dns_packet.id)
             dns_packet.z = 1
             print(dns_packet.show())


         while True:
            packet, dest = sock.recvfrom((1 << 16) - 1)
            ether = Ether(packet)
            egress = set() 

            if IP in ether:
                if ICMP in ether[IP]: print('imcp packet on interface', interface, ICMP(ether[IP][ICMP]))

                if ether[IP].haslayer(UDP):
                    packet = ether[IP][UDP]
                    sport, dport = packet.sport, packet.dport 
                    if dport == self.DNS_PORT:
                        print('egress traffic') 
                        if DNS in ether[IP][UDP][DNS]:
                            dns_packet = ether[IP][UDP][DNS]
                            if dns_packet.id not in egress:
                                with threadPool(max_workers=mp.cpu_count()) as childPool:
                                    childPool.submit(dns_threadHandler, (dns_packet,))
                            else:
                                print('packet leaving socket  on interface handled by process', interface, os.getpid())
                    elif sport == self.DNS_PORT:
                        print('ingress traffic' )
                        if DNS in ether[IP][UDP][DNS]:
                            dns_packet = ether[IP][UDP][DNS]
                            print('packet arriving socket  on interface handled by process', interface, os.getpid())

    def handleEgressTraffic(self):
        host: str = socket.gethostbyname(socket.gethostname())
        sock = None 
        if sys.platform == 'darwin' or sys.platform == 'win32':  
            interfaces_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            interfaces = [netifaces.ifaddress(x) for x in self.interfaces]
            sockBinds = [] 
            addr = [netifaces.ifaddresses(x) for x in self.interfaces]
            for iface in addr:
                for iaddress in addr[iface]:
                    if 'addr' in iaddress and isIpv4(iaddress['addr']):
                        sockBinds.append(isaddress['addr'])
        else:
            with pool(max_workers=mp.cpu_count()) as socket_dns_pool:
                socket_dns_pool.map(
                    self.listen_raw_socket, self.interfaces 
                )
        
            
            
if __name__ == "__main__":
    agent = Agent()
    agent.handleEgressTraffic()