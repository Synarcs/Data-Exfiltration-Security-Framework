#!/usr/bin/python3 

import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor 

start = int(time.time()) 

urls = [] 
responses = []

# create an list of 5000 sites to test with
for y in range(2000):urls.append("https://kv801.prod.do.dsp.mp.microsoft.com")

def send(url):
    print('current thread process :: ', threading.current_thread().getName())
    code = requests.get(url).status_code 
    if code != 200: responses.append(code) 

print('starting executor for concurrent pool runs of request')

with ThreadPoolExecutor(max_workers=len(urls)) as executor:
    for url in urls: executor.submit(send, url)
        
end = int(time.time()) 
print(str(round(len(urls)/(end - start),0))+"/sec")