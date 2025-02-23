#!/bin/bash 

while true; do OLD=$(netstat -su | grep "packets received" | awk '{print $1}'); sleep 1; NEW=$(netstat -su | grep "packets received" | awk '{print $1}'); echo "DNS QPS: $(($NEW - $OLD))"; done



# iperf bandwidth measure for link in kernel 
sudo iperf -s -u -p 53 
