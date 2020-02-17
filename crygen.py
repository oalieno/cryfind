#!/usr/bin/env python3
import random
from crylib.constants import constants

def gen_yara(constants, prefix = 'cryfind'):
    rules = ''
    for constant in constants:
        rules += f'rule {prefix}_{random.getrandbits(40)} {{\n'
        rules += '    meta:\n'
        rules += f'        name = "{constant["name"]}"\n'
        rules += '    strings:\n'
        for index, value in enumerate(constant["values"]):
            rules += f'        $c{index} = {{ {" ".join(list(map(lambda x: hex(x)[2:].rjust(2, "0"), value)))} }}\n'
        rules += '    condition:\n'
        rules += f'        all of them\n'
        rules += '}\n\n'
    return rules

def main():
    print(gen_yara(constants))

if __name__ == '__main__':
    main()
