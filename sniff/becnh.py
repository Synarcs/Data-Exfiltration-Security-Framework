#!/bin/python3 
import os, sys 
import random , requests as rq , time 



# while true; do time python3 -c "import requests as rq; print(rq.get('https://kv801.prod.do.dsp.mp.microsoft.com/').status_code)";sudo python3 ../sniff/dns_ipv6.py; sleep 1; done;

# while true; do seq 10000 | xargs -n1 -P 10000 curl -s "https://kv01.prod.do.dsp.mp.microsoft.com/"; done

# parallel -j 100 "time dig +short kv801.prod.do.dsp.mp.microsoft.com" ::: {1..100}

domains = ["mx-ll-171.4.217-176.dynamic.3bb.co.th","kv801.prod.do.dsp.mp.microsoft.com", "dns.msftncsi.com"]


if __name__ == "__main__": 
    while True:
        #domain = random.choice(domains) 
        domain = domains[0]
        st = time.time()
        try:
            rq.get(f"https://{domain}").status_code
            print('[x] Total Time ::', time.time() - st)
            time.sleep(0.8)
        except Exception as err: 
            print('broke for domain', domain) 
            break 

