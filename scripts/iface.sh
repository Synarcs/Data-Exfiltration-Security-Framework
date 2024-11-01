#!/bin/bash

sudo ip netns 


sudo ip netns add sx1
sudo ip netns add sx2

sudo ip link add sx1-eth0 type veth peer name sx1-eth1

sudo ip link set sx1-eth0 netns sx1
sudo ip link set sx1-eth1 netns sx2

# configure interfaces for the veth pairs via ip route layers 
sudo ip netns exec sx1 ip addr add 10.200.0.1/24 dev sx1-eth0
sudo ip netns exec sx2 ip addr add 10.200.0.2/24 dev sx1-eth1

# configure loopback interfaces
sudo ip netns exec sx1 ip link set lo up
sudo ip netns exec sx2 ip link set lo up

# configure interfaces for the veth pairs
sudo ip netns exec sx1 ip link set sx1-eth0 up
sudo ip netns exec sx2 ip link set sx1-eth1 up



sudo ip netns exec sx1 ip route add default via 10.200.0.1
sudo ip netns exec sx2 ip route add default via 10.200.0.2 


