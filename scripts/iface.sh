#!/bin/sh 

# use the netlink socket to get information of net inet sockets 
sudo apt install libnl-route-3-dev libnl-3-dev libev-dev 

# if index for deep egress monitoring 
sudo ip link add bpf_sx type dummy
sudo ip link set bpf_sx up
sudo ip addr add 10.2.0.0/16 dev bpf_sx 


sudo ip link show dev bpf_sx
sudo ip route show dev bpf_sx
# detach the interfaces ports from kernel using netlink 
sudo ip link del bpf_sx
