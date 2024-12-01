
pass=$1 

# iodine c2c server 
sudo iodined -f -P $1 10.0.0.1 t.bleed.io 

# iodine c2c client 
sudo iodine -P bleed -f -r 192.168.64.27 t.bleed.io 
 
