## Data Plane eBPF Node agent compilation steps and deploying instructions at the endpoint.

### Infrastructure Requriements at Endpoint
* The current installation steps assume, the endpoint runs ubuntu. The dependencies installation for all the required dependencies, asumme below mentioned infrastructure and kernel requirements are met.
* The eBPF agent compiled binary requires the following
    * Linux Kernel ( >= 5.2 )
    * CPU Architecture (ARM, x86_64, RISCV
    * 2048 MB of memory, and atleast 4 CPU for maximum parallel performance across kernel and userspace.


### Clone the repository at Endpoint
```
    git clone https://github.com/Synarcs/DNSObelisk
    cd DNSObelisk
```

### Install dependencies
```
    sudo apt update && sudo apt-get install build-essential
```

### install all the kernel headers, libbpf Go compiler other kernel packages and userspace packages.
```
    make build-dep-agent 
```

### Compile the agent binary 
```
    make build 
```

### Start prometheus node-exporters at endpoint for endpoint resource monitoring 
```
    make node-metrics
```

### modify the agent config to point the nodeIP's running prometheus metric server, kafka brokers, grafana visualization server (node_agent/config.yaml).
```
// start the agent, the agent is blocking and runs infintely at the endpoint across userspace and kernel to prevent DNS exfiltration attacks. 
    make run_node_agent & 
```

### verify agent injected eBPF kernel programs over TC Qdisc)
```
    tc qdisc show dev $(physical NIC's)  // (verify CLSACT QDISC attached to all netdev's and bridge interfaces).
```

### ONNX inference unix IPC mount paths 
```
    sudo lsof /run/dnsobelisk/onnx-inference-in.sock  
    sudo lsof /run/dnsobelisk/onnx-inference-out.sock
```

### finally verify all loaded eBPF kernel programs 

### all eBPF programs start with exfil_sec*, the surrounding program varies based on number of netdev's

### there must be program named classify attached to physical netdev.
```
// all the node agent dep install xdp-tools, bpftrace, bpftools, libbpf bindings, and kernel headers.
    sudo bpftool prog show  
    sudo bpftool map show
```

# dump internals of the eBPF map in the kernel managed vy the security framework 
```
    sudo bpftool map dump id <map_id>
```