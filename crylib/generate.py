from crylib.db import dbs
import random

def gen_yara():
    rules = ''
    for db in dbs:
        for constant in db.constants:
            rules += f'rule cryfind_{random.getrandbits(40)} {{\n'
            rules += '    meta:\n'
            rules += f'        algorithm = "{constant.algorithm}"\n'
            rules += f'        description = "{constant.description}"\n'
            rules += '    strings:\n'
            for index, value in enumerate(constant.values):
                rules += f'        $c{index} = {{ {" ".join(list(map(lambda x: hex(x)[2:].rjust(2, "0"), value)))} }}\n'
            rules += '    condition:\n'
            rules += f'        all of them\n'
            rules += '}\n\n'
    return rules
