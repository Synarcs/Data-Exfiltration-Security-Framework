### The distributed infrastructure for the framework, 
* The distributed infrastructure can be deployed on any cloud environments (public, private, hybrid), orchestrated environments (k8s), containers (podman, docker, lxc, vagrant), however to get quick started with on local builds the installation step provide the deployment steps.
* The distributed infrastructure primarily contains 3 core components 
    * PowerDNS Recursor
    * PowerDNS Authoritative Server
    * Apache Kafka
* Each of them can be replaced with internal enterprise adopted solutions for example (redis, activeMQ) over kafka, or any DNS server (bind, unbound), but the core eBPF agent implementation in data plane and control plane assume the following components are there in distributed infrastructure.
* ALl installation steps can be found under infrastructure/ folder.