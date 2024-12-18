import os
import dns.resolver
from typing import List
import pandas as pd 
import numpy as np
import csv 

# process the resolution for mail records for tld to analyze the most used host tld domains 

domains = []
out = os.path.join(os.getcwd(), 'mx_records.csv')

file_out = open(out, 'a')   

def get_mx_records(domain) -> List[str]:
    global domains
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = [str(record.exchange) for record in mx_records] 
        return mx 
    except Exception as err: pass 

txt_null_domains: List = []

def get_txt_records(domain) -> List[str]:
    global txt_null_domains 
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        txt_null_domains.append(**([x for x in txt_records.response.answer]))
        txt_null_domains.append(**([x for x in txt_records.response.additional]))


        null_records = dns.resolver.resolve(domain, 'NULL')
        txt_null_domains.append(**([x for x in null_records.response.answer]))

    except Exception as err: pass 


with open('top-host.csv', mode ='r', encoding='utf-8')as file:
    csvFile = csv.reader(file)
    for file in csvFile: 
        domains = get_mx_records(file[-1])
        if domains != None:
            mx_servers = pd.DataFrame(np.array(domains))
            mx_servers.to_csv(out, mode='a',index=False, header=False)
        domains = []
