#!/usr/bin/python3

import os 

globalDomains = ['cloud.google.com', 'aws.amazon.com']

# for not keep zone only as top A
def convert_dga_to_bench() -> None:
    if not os.path.exists('dga.txt'):
        return 
    s = []
    with open('dga.txt', 'r', encoding='utf-8') as zone_file:
        zones = zone_file.readlines()

    with open('queries.txt', 'w', encoding='utf-8') as stress_file:
        stress_file.writelines([zone + " A\n" for zone in zones] + [public_zones + ' A\n' for public_zones in globalDomains])

if __name__ == "__main__":
    convert_dga_to_bench()