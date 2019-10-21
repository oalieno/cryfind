#!/usr/bin/env python3
import sys
from docopt import docopt
from crylib.search import Search

__doc__ = f"""
Usage:
{sys.argv[0]} [-l VALUE] <filename>

Options:
-h --help                Show this screen
-l VALUE --level VALUE   Specify search level, can be 1 or 2 [default: 1]
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
    banner()

    arguments = docopt(__doc__)
    filename = arguments['<filename>']
    level = int(arguments['--level'])

    search = Search(filename)
    search.run(level = level)

if __name__ == '__main__':
    main()

