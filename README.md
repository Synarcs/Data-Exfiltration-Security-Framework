<p align="center">
  <img src="docs/logo.jpg" width="300" height="290">
</p>


# DNS Data Exfiltration Security 
Enhanced observability and security solution built for enterprises to fully prevent DNS base exfiltration (C2, tunnelling, raw) with negligible data loss robust metrics, observability and tracing for malicious exfiltration attempts. Framework build for modern distributed cloud environments. orchestrated environments. High security running Deep Packet inspection directly inside Linux Kernel to prevent every DNS exfiltrated packet to passthrough. Runs eBPF across complete kernel network stack (TC, XDP, SOCK, SYSCALL), to prevent any exfiltration from host net_device to virtual encapsulated kernel traffic. Uses Deep learning in userspace and kafka data streaming and event analytics ensuring dynamic threat mitigation for both cloud-native build DNS infrastructures and legacy DNS topologies. Highly robust in preventing against DGA, safeguarding enterprises from any form of exfiltration happening via DNS. Proposes cloud-native DNS topologies for high security in preventing any type of exfiltration from DNS also ensuring HA with both peak performance and security.

Kernel 
* Kernel NEtwork Stack
    * XDP
    * Traffic Control 
    * Netfilter
    * Kernel Probes
    * Kernel Functions
    * Raw Tracepoints
* eBPF dynamic advanced maps and tracing for malicious events
    * BPF_MPA_TYPE_LRU_HASH
    * BPF_MAP_TYPE_RINGBUF
    * BPF_MAP_TYPE_HASH 


UserLand
* Cilium eBPF 
* Kafka Streams Producers
* Deep Learning
    * ONNX (Open Neural Network Exchange)
    * Tensorflow
    * Dense Neural Networks



DNS Network Topologies
* PowerDNS
* PowerDNS Authoritative Server
* PowerDNS Recursor 
* Apache Kafka


The framework is capable for 
* Severing C2 channels on creation. 
* Exposing C2 implants / APT malwares carrying DNS data exfiltration.
* Destroying DNS tunnels carrying exfiltration of any protocol over DNS.
* Destroying DNS tunnels and C2 channels carrying exfiltration of any protocol over DNS through any port irrespective of UDP transport
* Destroying tunnels in tunnels and reverse forwarded tunnels on compromised machines.
* Enhanced protection for in-build scan and prevention over kernel encapsulation mecahnicsms (VLAN, Tun/Tap, VXLAN).
* Hardened Security using seccomp, LSM, BPF secured map pinning, and BPF map lockings to protect all eBPF maps inside Linux kernel. 
* Build to prevent DGA (Domain generation algorithms), metrics with prometheus, grafana and practively adoptable for massively scaled infrastructures.
* Support to integrate itself with any XDR / EDR solutions providie metrics for centralized enterprise monitoring tools.
* Modular design to integrate across several legacy and modern cloud-native DNS topologies.


## Future Plans 
* Started Integration with Kubernetes as sidecar and gaurd contaienrs for all pods, run eBPF over kernel SOCK layer (skb_filter, skb_ops).
* Dynamic Injection of Cilium L7 DNS Network Policiy, and L3 Network Policity for Cilium agent and DNS proxy to block DNS and l3 ipv4 and ipv6 traffic from malicious remote C2 servers over Kubernetes pods via cilium eBPF reliance on SOCK layer before it reaches kernel traffic control on the host ned_device for eBPF DNS security agent to filter traffic. 
* Enhance security covering all attack vectors for DNS data exfiltration over TCP (as covered in UDP). 
* Integration with Kubernetes mutation webhooks for dynamic exfiltration guard security containers to be injected on pods matching required security labels.
* Harden security integrating with KubeArmor and other ACL policies for hardened security in orcehstrated environments.
* Support prometheus metrics endpoints integrated inside the sidecar. 
* Enhance framework for safeguarding enterprises from exfiltration over other protocols (ICMP, FTP) etc. 
* Enhance  support for DOT (DNS over TLS). 
* Add support for XDP ingress NXDOMAIN flood prevention to break DNS woter torture flood attacks. 

## Authors
- [Vedang Parasnis](https://github.com/Synarcs/)

