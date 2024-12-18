#!/bin/bash 

# tunnel traffic via the host link for the respective transfer bridge 
sudo ip link add vxlan0 type vxlan id 100 remote 192.168.64.21 dstport 4789 dev enp0s1

# transport for layer vxland tunnel in kernel 
# add l3 for addr 
sudo ip addr add 192.120.0.1/24 dev vxlan0

sudo ip link set vxlan0 up

sudo ip link add vxlan0 type vxlan id 100 remote 192.168.64.25 dstport 4789 dev enp0s1
sudo ip addr add 192.120.0.2/24 dev vxlan0

sudo ip link set vxlan0 up