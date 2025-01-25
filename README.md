<p align="center">
  <img src="docs/logo.jpg" width="300" height="290">
</p>


# DNS Data Exfiltration Security 
Enhanced observability and security solution built for enterprises to fully prevent DNS base exfiltration (C2, tunnelling, raw) with negligible data loss robust metrics, observability and tracing for malicious exfiltration attempts. Framework build for modern distributed cloud environments. orchestrated environments. High security running Deep Packet inspection inside Linux Kernel to prevent every DNS exfiltrated packet to passthrough. Runs eBPF across complete kernel network stack (TC, XDP, SOCK, SYSCALL), to prevent any exfiltration from host net_device to virtual encapsulated kernel traffic. Uses Deep learning in userspace and kafka data streaming and event analytics ensuring dynamic threat mitigation for both cloud-native build DNS infrastructures and legacy DNS topologies. Highly robust in preventing against DGA, safeguarding enterprises from any form of exfiltration happening via DNS. 

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
* Destroying DNS tunnels and C2 channels carrying exfiltration of any protocol over DNS through any port irrespective of UDP or TCP transport
* Destroying tunnels in tunnels and reverse forwarded tunnels on compromised machines.
* Enhanced protection for in-build scan and prevention over kernel encapsulation mecahnicsms (VLAN, Tun/Tap, VXLAN).
* Build to prevent DGA (Domain generation algorithms), metrics with prometheus, grafana and practively adoptable for massively scaled infrastructures.
* Has support to integrate itself with any XDR / EDR solutions providie metrics for centralized enterprise monitoring tools.




## Authors
- [Vedang Parasnis](https://github.com/Synarcs/)


<a href="https://www.buymeacoffee.com/ericdolch"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" height="20px"></a>