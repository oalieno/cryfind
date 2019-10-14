#!/usr/bin/env python3
import sys
from crylib.search import Search

def banner():
    print('''
 ▄▄· ▄▄▄   ▄· ▄▌·▄▄▄▪   ▐ ▄ ·▄▄▄▄  
▐█ ▌▪▀▄ █·▐█▪██▌▐▄▄·██ •█▌▐███▪ ██ 
██ ▄▄▐▀▀▄ ▐█▌▐█▪██▪ ▐█·▐█▐▐▌▐█· ▐█▌
▐███▌▐█•█▌ ▐█▀·.██▌.▐█▌██▐█▌██. ██ 
·▀▀▀ .▀  ▀  ▀ • ▀▀▀ ▀▀▀▀▀ █▪▀▀▀▀▀• 
''')

def main():
    if len(sys.argv) < 2:
        print('Usage: cryfind filename')
        exit()

    banner()
    filename = sys.argv[1]
    search = Search(filename)
    search.run()

if __name__ == '__main__':
    main()

