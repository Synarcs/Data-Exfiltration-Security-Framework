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
    linux-headers-$(uname -r) \
    cmake \
    zlib1g-dev \
    pkg-config \
    bpfcc-tools \
    linux-tools-$(uname -r) \
    linux-tools-common \
    xdp-tools \
    bpftrace \
    strace \
    git \
    autoconf \
    libcap-dev \
    vim \
    curl \
    libdebuginfod-dev \
    bison \
    flex \
    libtool \
    protobuf-compiler \
    libcurl4-openssl-dev \
    libedit-dev \
    libsasl2-dev \
    librdkafka-dev \
    inetutils-ping \
    bsdmainutils \
    liburing-dev \
    iptables \
    iproute2 \
    libssl-dev \
    libncurses5-dev \
    libsqlite3-dev \
    libreadline-dev \
    libtk8.6 \
    libgdbm-dev \
    libpcap-dev \
    libffi-dev \
    libncursesw5-dev \
    tk-dev \
    libc6-dev \
    libbz2-dev

RUN echo "installing kernel network utilities and userspace eBPF go bindings" && \ 
                apt install -y iproute2 iptables bison conntrack 
SHELL [ "/bin/bash" , "-c" ]

# Install bpftool
RUN echo "install bpftool for libbpf bindings" && \
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool && \
    git submodule update --init && \
    cd src && \
    make install

RUN apt-get install -y libpcap-dev wget libgrpc++-dev

ADD kernel kernel/
ADD node_agent node_agent/
ADD cmd cmd/
ADD pkg pkg/
ADD data data/
ADD model model/
ADD scripts scripts/
ADD exfil_sec_api exfil_sec_api/
ADD go.mod .
ADD go.sum .
ADD Makefile .


ARG ARCH=arm64
# Install GVM and Go in a single layer
RUN curl -LO https://go.dev/dl/go1.23.2.linux-${ARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.23.2.linux-${ARCH}.tar.gz && \
    rm go1.23.2.linux-${ARCH}.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

# grpc protooc build bindings 
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest


# all the onnx runtime are used for inference and not training once model is trained and serialized in onnx, the agent assume the onnx model exist
ARG ONNX_VERSION=1.22.0

RUN set -eux; \
    arch="$(uname -m)"; \
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then \
        arch="x64"; \
    fi; \
    cd /tmp; \
    wget -O onnx.tgz "https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/onnxruntime-linux-${arch}-${ONNX_VERSION}.tgz"; \
    tar -xvf onnx.tgz; \
    rm -f onnx.tgz; \
    cd onnxruntime-linux-${arch}-${ONNX_VERSION}; \
    cp -r include/* /usr/include/; \
    cp lib/libonnxruntime.so.1 /usr/lib/; \
    cp lib/libonnxruntime.so /usr/lib/; \
    ldconfig; \
    cd /; \
    rm -rf "/tmp/onnxruntime-linux-${arch}-${ONNX_VERSION}"

# Build eBPF node-agent both in user and kernel space
RUN echo "Building kernel eBPF programs && user eBPF agent" && \
    make build
# expose metrics port for eBPF node-agent in usr space and export for kernel metrics 
# {profiler, prometheus metrics exporter}
EXPOSE 8080 3232
