#!/bin/sh 

set -eo 
echo "px] Install llvm clang and kernel bindings for ebpf"
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
    liburing-dev \
    iptables \
    iproute2 


sudo apt install -y \
    libssl-dev libncurses5-dev libsqlite3-dev libreadline-dev libtk8.6 libgdm-dev libpcap-dev

sudo apt-get install libffi-dev \
    libncursesw5-dev libssl-dev \
    libsqlite3-dev tk-dev libgdbm-dev \
    libc6-dev libbz2-dev

arch=$(uname -m)
if [[ $? -eq 0 ]]; then 
    if [[ $arch == "x86_64" ]]; then
        # x86_x64 cpu arch libc, libc bindings for i386 cpu architectures 
        sudo apt-get install libc6-dev-i386
    fi 
fi 



if [ $? -eq 0 ]; then 
    echo "Installed the kernel build librries"
else
    echo "Error Installing the kernel build librries"
    
fi 


wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 14
    

# git clone https://github.com/pyenv/pyenv.git ~/.pyenv
# install go 
# sudo apt-get install bison
# bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
# gvm install -B go1.22.0
# gvm use go1.22.0 

echo "install bazel bindings"
sudo apt install -y apt-transport-https curl gnupg
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings/
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://bazel.build/apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list


sudo apt install -y \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python-is-python3 \
    python3-setuptools \
    python3-wheel \
    python3-virtualenv
