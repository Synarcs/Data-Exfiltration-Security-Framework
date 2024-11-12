#!/bin/bash 

sudo dnf install named

echo "nameserver 192.168.64.26" | sudo tee /etc/resolv.conf

