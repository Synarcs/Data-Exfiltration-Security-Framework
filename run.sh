#!/bin/sh 

# use this to boot the eBPF EDR agent at the endpoint from packaged binary 

set -e

echo "Init the network ns topology at the endpoint .... "
bash usr/bin/brctl.sh


echo "Starting the EDR eBPF endpoint agent"
cd usr/bin/ && sudo ./main


