#!/usr/bin/env python3
import sys
from pathlib import Path
from docopt import docopt

from crylib import *
from crylib.constants import constants

__doc__ = f"""
Usage: cryfind [-s SOURCES] [-m METHODS] [-a] <filename>

Options:
-h --help           Show this screen
-s SOURCES          Sources to be searched, could be : plain, stackstrings [default: plain]
-m METHODS          Methods to be used, could be : string, xor, yara, peimport [default: string,yara]
-a --all            Use all methods and sources
"""

def banner():
    print('''
   ▄▄· ▄▄▄   ▄· ▄▌·▄▄▄▪   ▐ ▄ ·▄▄▄▄
  ▐█ ▌▪▀▄ █·▐█▪██▌▐▄▄·██ •█▌▐███▪ ██
  ██ ▄▄▐▀▀▄ ▐█▌▐█▪██▪ ▐█·▐█▐▐▌▐█· ▐█▌
  ▐███▌▐█•█▌ ▐█▀·.██▌.▐█▌██▐█▌██. ██
  ·▀▀▀ .▀  ▀  ▀ • ▀▀▀ ▀▀▀▀▀ █▪▀▀▀▀▀•
''')

def header(source, method):
    print('=' * 30)
    print(f'Source : {source}')
    print(f'Method : {method}')
    print('=' * 30)
    print()

def show(results):
    if len(results) > 0:
        pad = len(f'{max([result["address"] for result in results]):x}')
        pad = pad + pad % 2
        for result in sorted(results, key = lambda x : x['address']):
            print(f'[+] 0x{result["address"]:0{pad}x}')
            print(f'    - name : {result["name"]}')
            if result.get("xor"):
                print(f'    - xor  : 0x{result["xor"]:02x}')
    else:
        print('[-] I found nothing')
    print()

def show_pe_import(results):
    if len(results) > 0:
        for result in results:
            print(f'[+] {result["dll"]} - {result["function"]}')
    else:
        print('[-] I found nothing')
    print()

def main():
    arguments = docopt(__doc__)
    filename = arguments['<filename>']
    sources = arguments['-s'].split(',')
    methods = arguments['-m'].split(',')
    if arguments['--all']:
        sources = 'plain,stackstrings'.split(',')
        methods = 'string,xor,yara,peimport'.split(',')

    banner()

    with open(filename, 'rb') as f:
        binary = f.read()

    rules = []
    for rule in Path(__file__).parent.glob('rules/*'):
        with open(str(rule)) as f:
            rules.append(f.read())

    for source in sources:
        if source == 'plain':
            data = binary
        elif source == 'stackstrings':
            data = stackstrings(binary)
        else:
            raise ValueError(f'Unknown method name {method}')
        for method in methods:
            header(source, method)
            if method == 'string':
                show(find_const(data, constants))
            elif method == 'xor':
                show(find_const(data, constants, xor = True))
            elif method == 'yara':
                show(find_const_yara(data, rules))
            elif method == 'peimport':
                show_pe_import(pe_import(data))
            else:
                raise ValueError(f'Unknown source name {source}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] You Pressed Ctrl-C")
