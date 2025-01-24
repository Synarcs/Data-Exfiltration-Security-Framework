# RUN the agent image in k8s with seccomp, NET_ADMIN, BPF AND CAP_NET_RAW for proper kernel packet processing 

FROM ubuntu:latest 

USER root 
ARG OWNER=synarcs 

ENV MUTATE_PORT=3000 
WORKDIR /opt 

RUN echo "Required Kernel dependencies for eBPF kernel programs" && apt update -y && sudo apt install -y \
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


ADD node_agent/ .
ADD pkg/ .




