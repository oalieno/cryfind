#!/usr/bin/env python3
import sys
import yara
from lib.db import dbs, print_stats, print_db

def print_result(algo, address, description):
    print(f'[+] {algo}::{address:08x}')
    if description: print(f'    ↳ Description: {description}')

def search_collection(binary, collection):
    address = []
    for constant in collection['constants']:
        if constant in binary:
            address.append(binary.find(constant))
    return address

def search(binary, dbs):
    for db in dbs:
        hit = False
        print_db(db.description.get('title'), db.description.get('url'))
        for algo, collections in db.collections.items():
            for collection in collections:
                address = search_collection(binary, collection)
                if len(address) == len(collection['constants']):
                    hit = True
                    print_result(algo, min(address), collection['description'])
        if not hit: print('[-] No Known Crypto Signature Found')

def search_yara(binary, rule):
    hit = False
    print_db('Yara-Rules Crypto Signatures', 'https://github.com/Yara-Rules/rules/blob/master/Crypto/crypto_signatures.yar')
    y = yara.compile(source = rule)
    matches = y.match(data = binary)
    for match in matches:
        hit = True
        algo, address = match.rule, match.strings[0][0]
        print_result(algo, address, '')
    if not hit: print('[-] No Known Crypto Signature Found')

def banner():
    print('''
 ▄▄· ▄▄▄   ▄· ▄▌·▄▄▄▪   ▐ ▄ ·▄▄▄▄  
▐█ ▌▪▀▄ █·▐█▪██▌▐▄▄·██ •█▌▐███▪ ██ 
██ ▄▄▐▀▀▄ ▐█▌▐█▪██▪ ▐█·▐█▐▐▌▐█· ▐█▌
▐███▌▐█•█▌ ▐█▀·.██▌.▐█▌██▐█▌██. ██ 
·▀▀▀ .▀  ▀  ▀ • ▀▀▀ ▀▀▀▀▀ █▪▀▀▀▀▀• 
''')
    print_stats(dbs)

def main():
    if len(sys.argv) < 2:
        print('Usage: cryfind filename')
        exit()

    banner()

    filename = sys.argv[1]
    binary = open(filename, 'rb').read()
    rule = open('findcrypt3.rules').read()

    search(binary, dbs)
    search_yara(binary, rule)

if __name__ == '__main__':
    main()

