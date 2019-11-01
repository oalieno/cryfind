#!/usr/bin/env python3
import sys
from docopt import docopt
from crylib.search import Search

__doc__ = f"""
Usage:
{sys.argv[0]} [-s] <filename>

Options:
-h --help           Show this screen
-s --stackstrings   Enable stackstrings search, which use ida script [default: False]
"""

def banner():
    print('''
 ▄▄· ▄▄▄   ▄· ▄▌·▄▄▄▪   ▐ ▄ ·▄▄▄▄  
▐█ ▌▪▀▄ █·▐█▪██▌▐▄▄·██ •█▌▐███▪ ██ 
██ ▄▄▐▀▀▄ ▐█▌▐█▪██▪ ▐█·▐█▐▐▌▐█· ▐█▌
▐███▌▐█•█▌ ▐█▀·.██▌.▐█▌██▐█▌██. ██ 
·▀▀▀ .▀  ▀  ▀ • ▀▀▀ ▀▀▀▀▀ █▪▀▀▀▀▀• 
''')

def main():
    arguments = docopt(__doc__)
    filename = arguments['<filename>']
    stackstrings = arguments['--stackstrings']

    exclude_methods = ['Stackstrings']
    if stackstrings:
        exclude_methods.remove('Stackstrings')

    banner()

    search = Search(filename)
    search.run(exclude_methods)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] You Pressed Ctrl-C")

