#holds and process all thhe mutation exfil domains 
import os , random 
from typing import List 
import psycopg2 as pg 
from argparse import ArgumentParser 
from wonderwords import RandomWord
import subprocess 

DGA_FILE: str = 'dga.txt'
PDNS_AUTH_DOMAIN_SERVER: str = '10.158.82.55' # ip where pdns auth server runs 
PDNS_AUTH_DOMAIN_SERVER_PORT:str = '5353' # ip where pdns auth server forward port runs 
exfil_tools: List[str] = ['dnscat', 'sliver', 'iodine', 'nuages']

DNS_C2_EXFIL_SERVER: str = '10.158.82.53'
DEBUG: bool = False 

DEFAULT_FORWARD_ZONE = 'forward-zones=t.bleed.io=10.158.82.55:5353,bleed.io=10.158.82.55:5353,sliver.bleed.io=10.158.82.53:53,dnscat.bleed.io=10.158.82.55:5353,weasel.bleed.io=10.158.82.55:53,strive.io=10.158.82.55:5353,dnscat.strive.io=10.158.82.55:5353'

def gen_exil_domain(charsAllowed, vis, mxLen, i, charSet: List, tld: str, exfil_host_domains: List[str]):
    if i == mxLen:  
        exfil_host_domains.append(f'{''.join(charSet)}.{tld}')
        return exfil_host_domains

    for ind in range(len(charsAllowed)):
        if not vis[ind]:
            vis[ind] = True
            charSet.append(charsAllowed[ind])
            gen_exil_domain(charsAllowed, vis, mxLen, i + 1, charSet, tld, exfil_host_domains)
            charSet.pop() 
            vis[ind] = False 
    
    return exfil_host_domains

def gen_exil_tld_domains(tldDomains: List[str], slds: List[str]) -> None:
    exfil_root_domains: List[str] = []
    for tld in tldDomains:
        for sld in slds:
            exfil_host_domains: List = []
            gen_exil_domain(list(sld), [False for x in range(len(sld))], len(sld), 0, [], tld, exfil_host_domains)
            for x in exfil_host_domains: exfil_root_domains.append(x)
    return exfil_root_domains


def gen_c2_exfil_domains(tldDomains: List[str], c2_tool_domains: List[str]) -> None:
    ans = []
    for exfil_c2 in c2_tool_domains:
        for y in tldDomains:
            ans.append(f'{exfil_c2}.{y.lower()}')
    return ans 

def gen_exil_forward_zones(dga: List[str]) -> None:
    vis = set() 
    ss = DEFAULT_FORWARD_ZONE + ","
    for zone in dga:
        labels = zone.split('.')
        if 'sliver' in zone:
            ss += f'{zone}={DNS_C2_EXFIL_SERVER}:53' # keep the exfil port for slier as 53 as thr forward zone to forward upstream query to the sliver c2 server 
            ss += ","
            if len(labels) > 2 and f'{labels[1]}.{labels[2]}' not in vis:
                ss += f'{labels[1]}.{labels[2]}={DNS_C2_EXFIL_SERVER}:53' 
                ss += "," 
                vis.add(f'{labels[1]}.{labels[2]}')
        else:
            ss += f'{zone}={PDNS_AUTH_DOMAIN_SERVER}:{PDNS_AUTH_DOMAIN_SERVER_PORT}'
            ss += ","
            if len(labels) > 2 and f'{labels[1]}.{labels[2]}' not in vis:
                ss += f'{labels[1]}.{labels[2]}={PDNS_AUTH_DOMAIN_SERVER}:{PDNS_AUTH_DOMAIN_SERVER_PORT}'
                ss += ","
                vis.add(f'{labels[1]}.{labels[2]}')
    ss = ss[:len(ss) - 1] 
    return ss 

def replace_aoth_forward_zone_pdns_recursor(forward_path: str) -> None:
    path: str = "/etc/powerdns/recursor.conf"
    if not os.path.exists(path):
        print('pdns recursor file not found ', path)
        return RuntimeError('pdns recursor file not found')
    with open(path, 'r') as file:
        lines = file.readlines()
    
    for i, line in enumerate(lines):
        if line.startswith('forward-zones='):
            lines[i] = forward_path + '\n'
            break 
    
    with open(path, 'w') as file:
        file.writelines(lines)


def append_zone_data_in_zoneFiles(dga: List[str]) -> None:
    vis = set() 
    for domain in dga:
        labels = domain.split('.') 
        exfil_tool = labels[0]
        zone = '.'.join(labels[1:])
        root_zone = [  # for now keep only one server cssvlab06 to carry out data breaches 
            f"pdnsutil create-zone {zone}.",
            f"pdnsutil set-kind {zone}. NATIVE",
            f"pdnsutil add-record {zone}. @ A 300 10.158.82.53",
            f"pdnsutil add-record {zone}. {exfil_tool} NS 3600 ns1.{exfil_tool}.{zone}",
            f"pdnsutil add-record {zone}. ns1.{exfil_tool} A 3600 10.158.82.53"
        ]         
        exfil_zone_commands  = [
            f"pdnsutil create-zone {exfil_tool}.{zone}.",
            f"pdnsutil set-kind {exfil_tool}.{zone}. NATIVE",
            f"pdnsutil add-record {exfil_tool}.{zone}. @ A 3600 10.158.82.53",
            f"pdnsutil add-record {exfil_tool}.{zone}. @ NS 3600 ns1.{exfil_tool}.{zone}",
            f"pdnsutil add-record {exfil_tool}.{zone}. ns1 A 3600 10.158.82.53"
        ]     

        if DEBUG:
            print('commands are', root_zone + exfil_zone_commands) 
        try:
            if zone not in vis:
                # the exfil malicious generates dga to generate randomd omains (tld) + delegate NS for c2 exfil 
                for cmd in root_zone + exfil_zone_commands:
                    subprocess.run(cmd.split(), check=True)
                vis.add(zone)
            else:
                for cmd in exfil_zone_commands:
                    subprocess.run(cmd.split(), check=True)
        except Exception as err:
            print('error creating zone ', err) 
            return 
        

def clean_zones() -> bool:
    vis = set() 
    try:    
        with open(DGA_FILE, 'r', encoding='utf-8') as file:
            dga = file.readlines()
            for domain in dga:
                labels = domain.split('.')
                exfil_tool = labels[0] 
                zone = '.'.join(labels[1:]).strip()
                clean_command = [
                    f"pdnsutil delete-zone {domain.strip()}",
                ]
                if zone not in vis:
                    clean_command.append(
                        f"pdnsutil delete-zone {zone}",
                    )
                    vis.add(zone)

                if DEBUG:
                    print('clean command is ', clean_command)
                    
                for cmd in clean_command:
                    subprocess.run(cmd.split(), check=True) 
        
        replace_aoth_forward_zone_pdns_recursor(DEFAULT_FORWARD_ZONE)

        res = ['service', 'pdns-recursor', 'restart']
        subprocess.run(res, check=True)
        return True 
    except Exception as err:
        print(err)
        return False 

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('-c', '--clean', type=bool,required=False, default=False, help="clean the exfil domain from dga file")
    args = parser.parse_args()

    conn = pg.connect(host ='cssvlab08.uwb.edu',database='pdns', user='pdns', password='pdns_exfil')
    cursor = conn.cursor()
    if args.clean is not None and args.clean:
        if clean_zones():
            if os.path.exists(DGA_FILE):
                os.remove(DGA_FILE)
        else:
            print('the local zone file canot be cleaned until zones are cleaned on pdns recursor')

        cursor.execute('select * from malicious_domain')
        for row in cursor.fetchall():
            print(row)
    else:
        r = RandomWord()
        # max tld + sld + exil_dom (label 1) == 2 + 6 + 9 + = 15 --> (255 - 15) = 240 exfil entropy
        # min tld + sld (label 1) == 2 + 1 + 1 = 4 --> (255 - 4) = 251 exfil entropy
        # dga = gen_c2_exfil_domains(tldDomains=[RandomWord(max_word_size=9, constant_word_size=True, include_digits=False, include_special_chars=False).generate() + ".io" 
                                            #    for _ in range(1 << 16)], 
                                    # c2_tool_domains=exfil_tools)
        dga = gen_c2_exfil_domains(tldDomains=[r.word() + ".io" 
                                       for _ in range(1 << 0)], 
                            c2_tool_domains=exfil_tools)
        ff = open(DGA_FILE, 'w', encoding='utf-8')
        ff.write('\n'.join(dga))

        print(dga) 
        ffw = gen_exil_forward_zones(dga) # get the exfil ports and forward zone val 

        print(ffw)

        append_zone_data_in_zoneFiles(dga)
        replace_aoth_forward_zone_pdns_recursor(ffw)

        # print(ffw[:20])

    cursor.close()
    conn.close()

