#!/bin/sh 

auth_serv_ip=$1 

set -e 

which pdnsutil 
if [[ $? -eq 0 ]]; then 
    echo "error pdnsutil required for processing zone information in pdns auth server"
fi 


# create the root parent zone for exfil 
pdnsutil create-zone sliver.bleed.io 
pdnsutil create-zone dnscat2.bleed.io 
pdnsutil create-zone iodine.bleed.io 
pdnsutil create-zone stealh.bleed.io 


addZoneRecords(zone, exfil_tool) {
    pdnsutil create-zone $zone 
    pdnutil add-record $zone dnscat NS ns1.$exfil_tool.$zone 
    pdnutil add-record $zone ns1.$exfil_tool A $auth_serv_ip 

    pdnsutil create-zone $exfil_tool.$exfil_tool
    pdnsutil add-record $exfil_tool.$exfil_tool @ NS ns1.$exfil_tool.$exfil_tool
    pdnutil add-record $exfil_tool.$exfil_tool ns1.$exfil_tool A $auth_serv_ip 
}

cleanZones() {
    pdnsutil delete-zone sliver.bleed.io 
    pdnsutil delete-zone dnscat2.bleed.io 
    pdnsutil delete-zone iodine.bleed.io 
    pdnsutil delete-zone stealh.bleed.io 
}


for i in {1..8}; do 

done;
