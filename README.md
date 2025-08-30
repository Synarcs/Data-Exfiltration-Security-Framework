<p align="center">
  <img src="docs/logo.jpg" width="300" height="290">
</p>


# DNS Data Exfiltration Security 
Enhanced observability and security solution built for enterprises to fully prevent DNS base exfiltration (C2, tunnelling, raw) with negligible data loss robust metrics, observability and tracing for malicious exfiltration attempts. Framework build for modern distributed cloud environments. orchestrated environments. High security running Deep Packet inspection directly inside Linux Kernel to prevent every DNS exfiltrated packet to passthrough. Runs eBPF across complete kernel network stack (TC, XDP, SOCK, SYSCALL), to prevent any exfiltration from host net_device to virtual encapsulated kernel traffic. Uses Deep learning in userspace and kafka data streaming and event analytics ensuring dynamic threat mitigation for both cloud-native build DNS infrastructures and legacy DNS topologies. Highly robust in preventing against DGA, safeguarding enterprises from any form of exfiltration happening via DNS. Proposes cloud-native DNS topologies for high security in preventing any type of exfiltration from DNS also ensuring HA with both peak performance and security. Introduces novel approach referred as kernel enforced dynamic security for endpoint detection and response a wrapper to aid enterpirse EDR / XDR solutions with dynamic network policies, network filters, cloud infrastructure NACL's for cross protocol exfiltration prevention (l3, l4, l7) once prevented via DNS.


# Vision
Introduces a novel approach termed Kernel-Enforced Dynamic Security (KEDS) for Endpoint Detection and Response (XDR / EDR), acting as a wrapper to enhance enterprise EDR/XDR solutions.
KEDS provides real-time, kernel-level enforcement of dynamic network policies, fine-grained traffic filters, and cloud infrastructure NACLs to prevent cross-protocol exfiltration across layers L3 (IP), L4 (Transport), and L7 (Application) — especially effective following initial prevention at the DNS layer.


## Node Agent

Kernel 
* Kernel NEtwork Stack
    * XDP
    * Traffic Control  (CLSACT)
    * Kernel Probes
    * Kernel Functions
    * Raw Tracepoints (kernel schedulers, software netdev device drivers)
    * Kernel Socket layer (cgroup_egress)
    * Kernel LSM (BPF Security Hooks BPF_PROG_LOAD, secured sign verification)
* eBPF dynamic advanced maps and tracing for malicious events
    * BPF_MAP_TYPE_LRU_HASH
    * BPF_MAP_TYPE_RINGBUF
    * BPF_MAP_TYPE_HASH
    * BPF_MAP_TYPE_LPM_TRIE
    * BPF_MAP_TYPE_ARRAY


UserLand 
* Cilium eBPF 
* Cilium CNI 
* Kafka Streams Producers
* Deep Learning
    * ONNX (Open Neural Network Exchange)
    * ONNX Model Quantization
    * Tensorflow
    * Dense Neural Networks
* GRPC over UDS - ONNX Inference RPC servers 
* Filter Chain Proxies for Segmented DPI
    * Envoy L7 Proxy, Custom L7 Filter chains paired with kernel sock parser eBPF DPI

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
* Destroying tunnels in tunnels and reverse forwarded tunnels on compromised machines further tunnelled through DNS for remote C2 communication.
* Enhanced protection for in-build scan and prevention over kernel encapsulation mecahnicsms (VLAN, Tun/Tap, VXLAN).
* Hardened Security using seccomp, LSM, BPF secured map pinning, and BPF map lockings to protect all eBPF maps inside Linux kernel. 
* Build to prevent DGA (Domain generation algorithms), metrics with prometheus, grafana and practively adoptable for massively scaled infrastructures.
* Support to integrate itself with any XDR / EDR solutions providie metrics for centralized enterprise monitoring tools.
* Modular design to integrate across several legacy and modern cloud-native DNS topologies.
* Robust adaptable to modern evolving threats and massively scalable for enterprise data planes, with Kafka threat events updating malicious domain cache in userspace across and security policies inside kernel across each node in data plane.

## Features In Development
* Rate Limiting
    * Malicious / Suspicious Requests per second window
        Implementation of Token Bucket Algorithm for rate-limiting DNS traffic over kernel TC egress QDISC (bpf_timer), with refill rate equals 1 sec kernel time-window per-cpu reference pinned reference per CPU.
    * Improve the DNS Volume base rate limiting
* Zero Trust Architecture with Dual Signatures and Mutual Authentication for eBPF programs loading in cloud distributed systems
	* Stage 1: Control Plane ↔ Data Plane
	* gRPC over mutual TLS (mTLS) used for secure communication,
	* Control plane signs eBPF programs, verified by the data plane during load.
	* Stage 2: Node ↔ Kernel
	* Kernel Keyring + BPF LSM hooks enforce signature verification of eBPF ELF programs,
	* Mirrors TLS certificate revocation logic over kernel process keyrings, supporting internal and parent Certificate Authorities for continuous validation and attestation.

## Future Plans 
* Cloud Providers Infrastructure Integration 
    * Integration with Public Cloud providers for dynamic NACL, Security groups, firewall rules creation over VPC for DNS exfiltration security
eBPF node agent rinning over host ns, to fully thwart data breach by killing malicious C2 implants.
* Enhance security covering all attack vectors for DNS data exfiltration over TCP (as covered in UDP) at endpoint itself, supporting conntrack state mapping in eBPF map for TCP handshake prior DNS transfer and stopping DNS data transfer over TCP socket via kernel TC.
    1.  Integrate  L7 TCP sock listener over user-space for coalesced tcp segments, for kernel to live forward TCP traffic from host netdev TC to envoy l7 socket listneer.
    2.  Implement a envoy GO wasm filter for deep parsing DNS traffic over TCP over unix stream socket and shared as component of core node-agent with similar hunt for process encap in kernel and userspace endpoint agent.
* Harden security integrating with KubeArmor and other ACL policies for hardened security in orchestrated environments.
* Enhance framework for safeguarding enterprises from exfiltration over other protocols (ICMP, FTP) etc. 
* Enhance support for DOT (DNS over TLS), eBPF based TLS fingerprinting interception in kernel. 
* Add support for XDP ingress NXDOMAIN flood prevention to break DNS woter torture flood attacks. 

## Building 

### Data Plane (eBPF Node Agent)
```
    bash infrastructure/agent.sh
    make build 
    make run_node_agent
```
### Control Plane 
```
    bash infrastructure/controller.sh 
    make build-controller
```

## Dependencies
* Data Plane (eBPF Node Agent): ``` infrastructure/agent.sh ```
* Control Plane: ``` infrastructure/controller.sh ```

## WhitePaper and supporting Paper
* [Security Framewok WhitePaper](https://github.com/Synarcs/DNSObelisk_Report) provides detailed internals of the security framework (the whitepaper is in process to be formelly published at upcoming USENIX Security, ACM and other security conferences).

## Author
- [Vedang Parasnis (Synarcs)](https://github.com/Synarcs/)

## Conferences
* Accepted and was presented at [Netdev 0x19](https://netdevconf.info/0x19/sessions/bof/real-time-prevention-of-dns-based-data-exfiltration-bof.html) for innovation in Linux kernel advancing DNS security.
* Accepted and was presented at [Linux Security Summit](https://sched.co/1zamI) for innovation in Linux kernel intersecting Kernel datapath, LSM, kprobes, tracepoints for advanced endpoint security solutions.
* Accepted at [Black Hat Breifings](https://www.blackhat.com/us-25/briefings/schedule/#kernel-enforced-dns-exfiltration-security-framework-built-for-cloud-environments-to-stop-data-breaches-via-dns-at-scale-45566) with honororium for groundbreaking research termed as kernel enforced endpoint security built specifically to enhance DNS security to nuetralize emerging C2 attack vectors scalable in distribtued environments with strength combat evolving C2 infrastructure attacks.

## Disclaimer
* This project is under heavy development focusing on a longer vision (Kernel enforced dynamic  security for detection and response) a privileged wrapper aiding EDR / XDR solutions, hence expect some bugs around it 😀😀😀

## Support 
<a href="https://www.buymeacoffee.com/vedangparan" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>


