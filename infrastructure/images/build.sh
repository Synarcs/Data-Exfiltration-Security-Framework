#!/binn/bash

echo "building docker images for dns c2 and tunnel exfil tools"

cd c2/

echo "building c2 docker images for dnscat2"
docker build -f Dockerfile.dnscat_client -t dnscat_client .
docker build -f Dockerfile.dnscat_server -t dnscat_server .


echo "building c2 docker images for dnscat2"
docker build -f Dockerfile.dnscat_client -t dnscat_client .
docker build -f Dockerfile.dnscat_server -t dnscat_server .

