#!/bin/sh

set -eo

echo "[✅] Installing Libraries, LLVM, Clang, and kernel bindings for eBPF to compile the eBPF agent"

sudo apt update -y && sudo apt install -y \
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
    libseccomp-dev \
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
    libbz2-dev \
    keyutils \
    libkeyutils-dev \
    policycoreutils-dev 

# dependencies for pprof flamegraph and other graph visualization support 
pprof=1
if [[ $pprof -eq 1 ]]; then 
    sudo apt install -y graphviz
fi 

# Install x86_64 specific libraries
arch=$(uname -m)
if [ "$arch" = "amd64" || "$arch" -eq "x86_64" ]; then 
    sudo apt install -y libc6-dev-i386
fi 

# Install Python dependencies
sudo apt install -y \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python-is-python3 \
    python3-setuptools \
    python3-wheel \
    python3-virtualenv \ 
    python3-command-runner 

agent_binary=1
if [[ $agent_binary -eq 1 ]]; then 
    sudo apt-get install -y ruby-rubygems
fi

# Install bpftool for btf emit and vmlinux for kprobes and kernel sockets 
echo "[✅] Building and installing bpftool"
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src 
make 
sudo make install
rm -rf bpftool

tcp_wasm_envoy_breach_sec=0 
if [[ $tcp_wasm_envoy_breach_sec -eq 1 ]]; then 
    wget -O- https://apt.envoyproxy.io/signing.key | sudo gpg --dearmor -o /etc/apt/keyrings/envoy-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/envoy-keyring.gpg] https://apt.envoyproxy.io focal main" | sudo tee /etc/apt/sources.list.d/envoy.list
    sudo apt-get update
    sudo apt-get install envoy
    envoy --version
fi 


# Install GVM and Go 1.23.2
echo "[✅] Installation gvm for go!"
echo "[x] Installing GVM (Go Version Manager)"
bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
source ~/.gvm/scripts/gvm
echo "[x] Installing Go 1.23.2"
gvm install go1.23.2 -B
gvm use go1.23.2 --default
source /home/vedpar/.gvm/scripts/gvm

# installing the python dependecnies for onnx runtime inference server 
sudo pip3 install -r model/infer/requirements.txt --break-system-packages

# install fpm for debian package build 
sudo apt-get install -y ruby-dev build-essential && sudo gem i fpm -f

# install node exporter 
wget https://github.com/prometheus/node_exporter/releases/download/v1.9.0/node_exporter-1.9.0.linux-amd64.tar.gz
tar -xvf node_exporter-1.9.0.linux-amd64.tar.gz && sudo mv node_exporter-1.9.0.linux-amd64 /opt 


echo "[✅] Installation completed successfully!"
