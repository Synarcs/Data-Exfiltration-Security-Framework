<p align="center">
  <img src="docs/logo.jpg" width="300" height="290">
</p>


# DNS Data Exfiltration Security 
An Enhanced observability and security solution to fully prevent DNS base exfiltration (C2, tunnelling, raw) with negligible data loss robust metrics, observability and tracing for malicious threads. Security framework build for modern distributed cloud environments. Runs enhanced security insdie Linux Kernel using eBPF, deep learning in userspace and Kafka for data streaming and event analytics ensuring dynamic threat mitigation for both cloud-native build DNS infrastructures and legacy DNS topologies.

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
* PowerDNS Reccursor 


The framework is capable for 
* Svering C2 channels on creation 
* Exposing C2 implants / APT malwares carrying DNS data exfiltration.
* Destroying DNS tunnels carrying exfiltration of any protocol over DNS.
* Real-time prevention of DNS data exfiltration over any random port
* Enhanced protection for in-build scan and prevention over kernel encapsulation mecahnicsms (VLAN, Tun/Tap, VXLAN).
* Build to prevent DGA (Domain generation algorithms), metrics with prometheus, grafana and practively adoptable for massively scaled infrastructures.

