#!/bin/bash

echo "[x] Linking the Systemd Resolved for the host network bridge for all host interfaces"
sudo unlink /etc/resolv.conf 


sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf