#!/bin/bash

#set -eo 

sudo apt-get install -y knot-dnsutils dnsperf

runDigTest() {
    echo "runn load over kdig for global benign domain $2"
    for ((outer = 1; outer <= $1; outer *= 10)); do
        echo "Running test with $outer iterations"
        time for inner in $(seq 1 1); do
            echo $inner | xargs -I {} -P $outer kdig +short $2 $3
        done
    done
}

domains=(console.google.com t.bleed.io dnscat.bleed.io)
recordType=A
i=10000

echo "Running eBPF Node-Agent DNS Stress test for exfil and malicious domains $domains[@] processId Stress test $$"
load () {
  for ((parallel=10000; parallel <= 1000000; parallel++)); do
     echo "running max parallel task $parallel"
     for domain in $(seq 1 ${#domains[@]}); do
	      runDigTest $i ${domains[domain]} $recordType
     done
  done
}

verifyPingLookup() {
	server=$1
	ping -c 1 $server >> /dev/null
	dig @$server google.com  >> /dev/null
}


while ff= read -r line; do
	if [[ "$line" =~ ^#.* ||  "${#line}" -eq 0 ]]; then
		continue
	else
		server=$( echo "$line" | cut -d " " -f 2)
		echo "runnin stress over eBPF Node agent agsinst DNS servers .." "${server:0:${#server}}"
		verifyPingLookup $server
		if [[ $? -eq 0 ]]; then
		  echo "DBS Ping passed"
		fi
	fi
done < /etc/resolv.conf

if [[ $? -eq 0 ]]; then
   echo "init stress test"
   load
fi
