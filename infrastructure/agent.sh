#!/bin/sh

set -eo

echo "[✅] Installing LLVM, Clang, and kernel bindings for eBPF"

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

# Install x86_64 specific libraries
arch=$(uname -m)
if [ "$arch" = "amd64" ]; then
    echo "[x] Installing x86_64 specific libraries"
    sudo apt install -y libc6-dev-i386
fi

install_bazel=0

if [[ $install_bazel -eq "1" ]]; then 
    echo "[x] Installing Bazel bindings"
    sudo apt install -y apt-transport-https curl gnupg
    curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/bazel-archive-keyring.gpg > /dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://bazel.build/apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
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
    python3-virtualenv


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
