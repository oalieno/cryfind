#!/usr/bin/env python3
import sys
from docopt import docopt
from crylib.search import Search
from crylib.generate import gen_yara

__doc__ = f"""
Usage:
{sys.argv[0]} [-s] <filename>
{sys.argv[0]} -g

Options:
-h --help           Show this screen
-s --stackstrings   Enable stackstrings search, which use ida script [default: False]
-g --generate       Generate yara rules from Constants DB
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
    generate = arguments['--generate']

    exclude_methods = ['Stackstrings']
    if stackstrings:
        exclude_methods.remove('Stackstrings')

    if generate:
        rules = gen_yara()
        print(rules)
    else:
        banner()
        search = Search(filename)
        search.run(exclude_methods)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] You Pressed Ctrl-C")

