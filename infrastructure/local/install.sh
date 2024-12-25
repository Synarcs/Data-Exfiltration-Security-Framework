#!/bin/bash 

sudo dnf install named

echo "nameserver 10.158.82.55" | sudo tee /etc/resolv.conf

