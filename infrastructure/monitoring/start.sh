#!/bin/bash 

bootNodeExporter() {
    ./node_exporter --web.listen-address="0.0.0.0:9100" & 
}


bootPrometheus() {
    ./prometheus --web.listen-address="0.0.0.0:9090" --config.file=./prometheus.yml & 
}

# bootEbpfExporterKernel() {
    # use the kernel cloud flare ebpf exporter running on socket kernel layer 
# }


bootNodeExporter
bootPrometheus
