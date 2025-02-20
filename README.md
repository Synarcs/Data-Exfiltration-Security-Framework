<p align="center">
  <img src="docs/logo.jpg" width="300" height="290">
</p>


# DNS Data Exfiltration Security 
Enhanced observability and security solution built for enterprises to fully prevent DNS base exfiltration (C2, tunnelling, raw) with negligible data loss robust metrics, observability and tracing for malicious exfiltration attempts. Framework build for modern distributed cloud environments. orchestrated environments. High security running Deep Packet inspection directly inside Linux Kernel to prevent every DNS exfiltrated packet to passthrough. Runs eBPF across complete kernel network stack (TC, XDP, SOCK, SYSCALL), to prevent any exfiltration from host net_device to virtual encapsulated kernel traffic. Uses Deep learning in userspace and kafka data streaming and event analytics ensuring dynamic threat mitigation for both cloud-native build DNS infrastructures and legacy DNS topologies. Highly robust in preventing against DGA, safeguarding enterprises from any form of exfiltration happening via DNS. Proposes cloud-native DNS topologies for high security in preventing any type of exfiltration from DNS also ensuring HA with both peak performance and security.

## Node Agent

Kernel 
* Kernel NEtwork Stack
    * XDP
    * Traffic Control 
    * Netfilter
    * Kernel Probes
    * Kernel Functions
    * Raw Tracepoints
* eBPF dynamic advanced maps and tracing for malicious events
    * BPF_MAP_TYPE_LRU_HASH
    * BPF_MAP_TYPE_RINGBUF
    * BPF_MAP_TYPE_HASH 


UserLand 
* Cilium eBPF 
* Cilium CNI 
* Envoy L7 Proxy, Filter chains 
* Kubernetes Client
* Kubernetes Sidecars, Kubernetes Mutating Webhooks 
* Kafka Streams Producers
* Deep Learning
    * ONNX (Open Neural Network Exchange)
    * Tensorflow
    * Dense Neural Networks

## Distributed Infrastructure
DNS Network Topologies
* PowerDNS
* PowerDNS Authoritative Server
* PowerDNS Recursor 
* Apache Kafka
* Apache Kafka Schema Registry


## Control Plane 
Threat Event Stream Message Analysis Control Plane Server 
* Apache Kafka (Producer, Consumer)
* Spring Kafka 
* Spring 
* Hibernate Spring JPA



## The framework Capabilities
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
* Robust adaptable to modern evolving threats and massively horizontally scaled data planes, with Kafka threat events updating malicious domain cache in userspace across each node in data plane. 


## Future Plans 
* Started Integration with Kubernetes as sidecar or gaurd contaienrs for all pods, run eBPF over kernel SOCK layer (skb_filter, skb_ops), feature to inherently support killing malicious pods carrying data breaches throughout k8s cluster.
* Dynamic Injection of Cilium L7 DNS Network Policiy, and L3 Network Policity for Cilium agent and DNS proxy to block DNS and l3 ipv4 and ipv6 exfiltrated traffic bidirectionally to remote malicious C2 servers carried through compromised k8s pods relying on cilium L7, L3, L4 filter proxies to filter in user space, before it reaches 
eBPF node agent rinning over host ns, to fully thwart data breach by killing malicious C2 implants.
* Enhance security covering all attack vectors for DNS data exfiltration over TCP (as covered in UDP). 
* Integration with Kubernetes mutation webhooks for dynamic exfiltration guard security containers to be injected on pods matching required security labels.
* Harden security integrating with KubeArmor and other ACL policies for hardened security in orcehstrated environments.
* Support prometheus metrics endpoints integrated inside the sidecar. 
* Enhance framework for safeguarding enterprises from exfiltration over other protocols (ICMP, FTP) etc. 
* Enhance support for DOT (DNS over TLS). 
* Add support for XDP ingress NXDOMAIN flood prevention to break DNS woter torture flood attacks. 


## Building 

### Data Plane (eBPF Node Agent)
```
    bash infrastructure/compile.sh
    make build 
    make run_node_agent
```
### Control Plane 
```
    bash infrastructure/controller.sh 
    make build-controller
```

## Dependencies
* Data Plane (eBPF Node Agent): ``` infrastructure/compile.sh ```
* Control Plane: ``` infrastructure/controller.sh ```

## Authors
- [Vedang Parasnis](https://github.com/Synarcs/)

## Support 
<a href="https://www.buymeacoffee.com/vedangparan" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>


