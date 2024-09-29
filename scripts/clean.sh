#!/bin/bash

echo "[x] Detaching Network NS from Bridge veth pair"
sudo ip netns exec sx1 ip link del sx1-eth0
sudo ip netns exec sx2 ip link del sx2-eth0

echo "[x] Cleaning the Network NS"
sudo ip netns del sx1
sudo ip netns del sx
echo "[x] Cleaning the bridge"
sudo ip link del br0

