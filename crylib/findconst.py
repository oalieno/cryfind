#!/usr/bin/env python3
import yara
from ahocorapy.keywordtree import KeywordTree
from collections import defaultdict

def _distance(items):
    return max(items) - min(items)

def _pick(picked, items):
    best = None
    for item in items:
        if best is None or _distance(picked + [item]) < _distance(picked + [best]):
            best = item
    return best

def _find_addresses(table, values):
    init, best = values[0], None
    for address in table.get(init, []):
        addresses = [address]
        for value in values[1:]:
            addresses += [_pick(addresses, table.get(value, []))]
            if None in addresses:
                return None
        if best is None or _distance(addresses) < _distance(best):
            best = sorted(addresses)
    return best

def _xordiff(data):
    answer = []
    for i in range(len(data) - 1):
        answer.append(data[i] ^ data[i+1])
    return bytes(answer)

def find_const(binarys, constants, xor = False):
    if type(binarys) is bytes:
        binarys = [binarys]
    
    kwtree = KeywordTree()
    for constant in constants:
        for value in constant['values']:
            kwtree.add(_xordiff(value) if xor else value)
    kwtree.finalize()

    results = []
    for binary in binarys:
        # get table of pattern location -> {b'abcd': 0x01, b'efgh': 0x06, ...}
        table = defaultdict(list)
        for value, address in kwtree.search_all(_xordiff(binary) if xor else binary):
            table[value].append(address)

        # find addresses of constant -> [0x01, 0x02, 0x03, 0x04]
        history = defaultdict(list)
        for constant in constants:
            addresses = _find_addresses(table, list(map(_xordiff, constant['values'])) if xor else constant['values'])
            if addresses and constant['name'] not in history.get(min(addresses), []):
                results.append({'name': constant['name'], 'address': min(addresses), 'xor': binary[addresses[0]] ^ constant['values'][0][0]})
                history[min(addresses)].append(constant['name'])

    return results

def find_const_yara(binarys, rules):
    if type(binarys) is bytes:
        binarys = [binarys]
    
    results = []
    for binary in binarys:
        for rule in rules:
            y = yara.compile(source = rule)
            matches = y.match(data = binary)
            for match in matches:
                name, address, meta = match.rule, match.strings[0][0], match.meta
                if 'cryfind' in name:
                    results.append({'name': f'{meta["algorithm"]} {meta["description"]}', 'address': address})
                else:
                    results.append({'name': name, 'address': address})
    
    return results
