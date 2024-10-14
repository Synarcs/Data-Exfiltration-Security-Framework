#!/bin/python3 
import os, sys 
import random , requests as rq , time 



# while true; do time python3 -c "import requests as rq; print(rq.get('https://kv801.prod.do.dsp.mp.microsoft.com/').status_code)"; sleep 1; done;

domains = ["mx-ll-171.4.217-176.dynamic.3bb.co.th","kv801.prod.do.dsp.mp.microsoft.com", "dns.msftncsi.com"]


if __name__ == "__main__": 
    while True:
        domain = random.choice(domains) 
        st = time.time()
        try:
            rq.get(f"https://{domain}").status_code
            print('[x] Total Time ::', time.time() - st)
            time.sleep(0.8)
        except Exception as err: 
            print('broke for domain', domain) 
            break 

