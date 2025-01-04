#holds and process all thhe mutation exfil domains 
import os 
from typing import List 
from functools import cache, wraps

exfil_host_domains: List = []

@cache 
def gen_exfil_domains(mx_ln: int = 5, domain_charsAllowed: List = [], vis: List = None, curr: str = "") -> None:
    if vis is None: vis = [False for x in range(len(domain_charsAllowed))]
        
    if mx_ln == 0:
        exfil_host_domains.append(f'{curr}.io')
        return

    for i in range(len(domain_charsAllowed)):
        if not vis[i]:
            vis[i] = True 
            curr += domain_charsAllowed[i]
            gen_exfil_domains(mx_ln - 1, domain_charsAllowed, vis, curr)
            curr = curr[:-1]
            vis[i] = False 


if __name__ == "__main__":
    chars = list('exfil')
    gen_exfil_domains(5, chars, None, "") 
    
    print(exfil_host_domains) 
