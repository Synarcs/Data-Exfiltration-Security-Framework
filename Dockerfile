# RUN the agent image in k8s with seccomp, NET_ADMIN, BPF AND CAP_NET_RAW for proper kernel packet processing 

FROM ubuntu:latest 

# needs kernel seccomp, tc, netfilter, raw pcap, for operation over kernel network stack
# this container must run in --previleged mode, or add capabilities manually CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF
# Most docker runs over ipc, htps, pid,,ns  linux ns in kernel unix socket cannot be mounted ensure the inference server is running on host and docker container has mounted volume 


USER root 
LABEL OWNER=synarcs 
LABEL EXFIL_SECURITY_MODE="DNS"
LABEL EXFIL_SECURITY="DATA Exfiltration Security Framework"

ENV MUTATE_PORT=3000 
WORKDIR /opt/kernel_sec

RUN echo "Required Kernel dependencies for eBPF kernel programs" && apt update -y && apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-tools \
    libelf-dev \
    libbpf-dev \
    # linux-headers-$(uname -r) \
    cmake \
    zlib1g-dev \
    pkg-config \
    bpfcc-tools \
    # linux-tools-$(uname -r) \
    # linux-tools-common \
    xdp-tools \
    bpftrace \
    strace \
    git \
    autoconf \
    libcap-dev \
    vim  \
    curl \ 
    libdebuginfod-dev \
    bison \
    flex \
    libtool \
    protobuf-compiler \
    libcurl4-openssl-dev \
    libedit-dev \
    libsasl2-dev  \
    librdkafka-dev \
    inetutils-ping \
    bsdmainutils \ 
    liburing-dev

RUN echo "installing kernel network utilities and userspace eBPF go bindings" && \ 
                apt install -y iproute2 iptables bison conntrack 
SHELL [ "/bin/bash" , "-c" ]

ENV GOROOT=/root/.gvm/gos/go1.23.2
ENV GOPATH=/root/go
ENV PATH=$GOROOT/bin:$GOPATH/bin:$PATH

# Install GVM and Go in a single layer
RUN curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer | bash && \
    /bin/bash -c "source /root/.gvm/scripts/gvm && \
    gvm install go1.23.2 -B && \
    gvm use --default go1.23.2"

# Install bpftool
RUN echo "install bpftool for libbpf bindings" && \
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool && \
    git submodule update --init && \
    cd src && \
    make install

RUN apt-get install -y libpcap-dev

ADD kernel kernel/
ADD node_agent node_agent/
ADD cmd cmd/
ADD pkg pkg/
ADD data data/
ADD scripts scripts/
ADD go.mod .
ADD go.sum .

# Build eBPF node-agent both in user and kernel space
RUN echo "Building kernel eBPF programs && user eBPF agent" && \
    cd node_agent && \
    make build
# expose metrics port for eBPF node-agent in usr space and export for kernel metrics 
EXPOSE 9092 
