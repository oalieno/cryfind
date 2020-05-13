import copy
import string
from collections import defaultdict

import yara
from ahocorapy.keywordtree import KeywordTree

class Node:
    def __init__(self, address, level):
        self.levels = [level]
        self.addresses = [address]

def _lmap(f, x):
    return list(map(f, x))

def _unique(x):
    return len(set(x)) == len(x)

def _distance(x, y):
    z = x.addresses + y.addresses
    return max(z) - min(z)

def _same_level(x, y):
    return len(set(x.levels) & set(y.levels)) > 0

def _merge(x, y):
    # ensure the levels is order after merge
    levels, addresses = [], []
    i, j = 0, 0
    while i < len(x.levels) and j < len(y.levels):
        if x.levels[i] < y.levels[j]:
            levels.append(x.levels[i])
            addresses.append(x.addresses[i])
            i += 1
        else:
            levels.append(y.levels[j])
            addresses.append(y.addresses[j])
            j += 1
    while i < len(x.levels):
        levels.append(x.levels[i])
        addresses.append(x.addresses[i])
        i += 1
    while j < len(y.levels):
        levels.append(y.levels[j])
        addresses.append(y.addresses[j])
        j += 1
    x.levels = levels
    x.addresses = addresses
    return x

def _find_addresses(table, values):
    lens = _lmap(lambda x: len(table[x]), values)
    if not _unique(values):
        return []
    elif sum(lens) > 100:
        # if too many nodes, use simple heuristic
        total = min(lens)
        groups = [[] for _ in range(total)]
        for value in values:
            xs = sorted(table[value])[:total]
            for i, x in enumerate(xs):
                groups[i].append(x)
        return groups
    else:
        nodes, total = [], min(lens)
        for i, value in enumerate(values):
            for address in table[value]:
                nodes.append(Node(address, i))

        complete = 0
        while complete < total:
            best_d, best_i, best_j = None, None, None
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    if not _same_level(nodes[i], nodes[j]):
                        d = _distance(nodes[i], nodes[j])
                        if best_d is None or d < best_d:
                            best_d, best_i, best_j = d, i, j
            if best_d is None:
                break

            if len(nodes[best_i].levels) + len(nodes[best_j].levels) == len(values):
                complete += 1
            nodes = nodes[:best_i] + \
                    nodes[best_i+1:best_j] + \
                    nodes[best_j+1:] + \
                    [_merge(nodes[best_i], nodes[best_j])]

        groups = []
        for node in nodes:
            if len(node.addresses) == len(values):
                groups.append(node.addresses)
        return groups

def _xordiff(data):
    answer = []
    for i in range(len(data) - 1):
        answer.append(data[i] ^ data[i+1])
    return bytes(answer)

def _two_complement(value, bits, i_byteorder='big', o_byteorder='big'):
    value = int.from_bytes(value, i_byteorder)
    if (value & (1 << (bits - 1))) != 0:
        value = value - (1 << bits)
    return abs(value).to_bytes(bits // 8, o_byteorder)

def _cut(x, n):
    ans = []
    for i in range(0, len(x), n):
        ans.append(x[i:i+n])
    return ans

def find_const(binarys, constants, encode=False, xor=False):
    if isinstance(binarys, bytes):
        binarys = [binarys]

    binarys, binarys_bak = copy.deepcopy(binarys), binarys

    constants_new = []
    for constant in constants:
        v = constant['values']

        constants_new.append({
            'name': constant['name'],
            'values': [v]
        })

        if encode:
            if b'\x00' * 3 in v:
                continue
            if all(map(lambda x: chr(x) in string.printable, v)):
                continue

            valueses = []
            if len(v) % 4 == 0:
                valueses.append(_cut(v, 4))
            if len(v) % 8 == 0:
                valueses.append(_cut(v, 8))
            for values in valueses:
                # big, little endian
                for e in ['big', 'little']:
                    constants_new.append({
                        'name': constant['name'],
                        'values': _lmap(lambda x: x[::-1] if e == 'little' else x, values),
                        'encode': f'{e} endian',
                        'size': len(values[0])
                    })
                # two's complement
                for i in ['big', 'little']:
                    for o in ['big', 'little']:
                        constants_new.append({
                            'name': constant['name'],
                            'values': _lmap(lambda x: _two_complement(x, len(x) * 8, i, o), values),
                            'encode': f"{i} endian -> two's complement -> {o} endian",
                            'size': len(values[0])
                        })

    constants, constants_bak = copy.deepcopy(constants_new), constants_new

    if xor:
        for constant in constants:
            constant['values'] = _lmap(_xordiff, constant['values'])
        binarys = _lmap(_xordiff, binarys)

    kwtree = KeywordTree()
    for constant in constants:
        for value in constant['values']:
            kwtree.add(value)
    kwtree.finalize()

    results = []
    for binary, binary_bak in zip(binarys, binarys_bak):
        # get table of pattern location -> {b'abcd': [0x01, 0x10], b'efgh': [0x06], ...}
        table = defaultdict(list)
        for value, address in kwtree.search_all(binary):
            table[value].append(address)

        # find addresses of constant -> [[0x01, 0x02, 0x03, 0x04], [0x10, 0x11, 0x12, 0x13]]
        for constant, constant_bak in zip(constants, constants_bak):
            groups = _find_addresses(table, constant['values'])
            for group in groups:
                result = {
                    'name': constant['name'],
                    'address': min(group),
                }
                if max(group) - min(group) != len(constant['values'][0]) * (len(constant['values']) - 1):
                    result['address_distribution'] = group
                xor = binary_bak[group[0]] ^ constant_bak['values'][0][0]
                if xor > 0:
                    result['xor'] = xor
                if constant.get('size'):
                    result['size'] = constant['size']
                if constant.get('encode'):
                    result['encode'] = constant['encode']
                results.append(result)

    return results

def find_const_yara(binarys, rules):
    if isinstance(binarys, bytes):
        binarys = [binarys]

    results = []
    for binary in binarys:
        for rule in rules:
            y = yara.compile(source=rule)
            matches = y.match(data=binary)
            for match in matches:
                _, address, meta = match.rule, match.strings[0][0], match.meta
                results.append({'name': meta['name'], 'address': address})

    return results
