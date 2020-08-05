import yara
import copy
import struct
from collections import defaultdict, deque
        
SIZE_STRING_INT = {
    'fullword': 0,
    'qword': 8,
    'dword': 4
}

class Value:
    def __init__(self, value, address, index, encoding):
        self.value = value
        self.address = address
        self.index = int(index)
        self.encoding = [
            'big',    # big endian
            'little', # little endian
            'bnb',    # big endian -> negative -> big endian
            'bnl',    # big endian -> negative -> little endian
            'lnb',    # little endian -> negative -> big endian
            'lnl',    # little endian -> negative -> little endian
        ][int(encoding)]

class Group:
    def __init__(self, blocksize, values):
        self.blocksize = blocksize
        self.values = values

class Result:
    def __init__(self, name):
        self.name = name
        self.groups = []

class Match:
    def __init__(self, match=None):
        self.values = { 0: [], 8: [], 4: [] }
        self.add(match)
    def add(self, match):
        if match:
            self.name = match.meta['name']
            self.length = match.meta['length']
            for address, varname, value in match.strings:
                _, size, index, encoding = varname.split('_')
                self.values[int(size)].append(Value(value, address, index, encoding))

def _cut(x, n):
    if n == 0:
        return [x]
    ans = []
    for i in range(0, len(x), n):
        ans.append(x[i:i+n])
    return ans

def _negative(value, c_type_in, c_type_out):
    value = struct.unpack(c_type_in, value)[0]
    return struct.pack(c_type_out, -value)

def _id_unique(values):
    _id, _values = [], []
    for i, value in enumerate(values):
        if value not in _values:
            _id.append(i)
            _values.append(value)
    return list(zip(_id, _values))

def _xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def _xor_difference(data, size = 1):
    ans = int.from_bytes(data[:-size], 'big') ^ int.from_bytes(data[size:], 'big')
    return ans.to_bytes(len(data) - size, 'big')

def _values_to_rule_strings(values, size=0):
    rules = ''
    c_type = {4: 'i', 8: 'q'}.get(size, '')
    for i, value in enumerate(values):
        for _id, encoding in _id_unique([
            value,
            value[::-1]
        ] + ([
            _negative(value, '>' + c_type, '>' + c_type),
            _negative(value, '>' + c_type, '<' + c_type),
            _negative(value, '<' + c_type, '>' + c_type),
            _negative(value, '<' + c_type, '<' + c_type)
        ] if size in [4, 8] else [])):
            rules += f'        $c_{size}_{i}_{_id} = {{ {encoding.hex()} }}\n'
    return rules

def _constant_to_rule(constant, sizes=['fullword'], _ctr=[0]):
    _ctr[0] += 1

    rules = f'''rule cry_{_ctr[0]} {{
    meta:
        id = {constant['id']}
        name = "{constant['name']}"
        length = {len(constant['value'])}
    strings:
'''
   
    conditions = []
    for size in sizes:
        size = SIZE_STRING_INT[size]
        if size > 0 and len(constant['value']) % size != 0:
            continue
        values = _cut(constant['value'], size)
        if any([b'\x00' * 3 in value for value in values]):
            continue
        rules += _values_to_rule_strings(values, size)
        conditions.append(' and '.join([f'(any of ($c_{size}_{i}_*))' for i in range(len(values))]))

    if not conditions:
        return ''
    
    rules += '    condition:\n'
    rules += '        ' + ' or '.join(conditions) + '\n'
    rules += '}\n'

    return rules

def _constants_to_rules(constants, sizes=['fullword']):
    rules = ''
    for i, constant in enumerate(constants):
        constant = {**constant, 'value': constant['value'][:64], 'id': i}
        rules += _constant_to_rule(constant, sizes)
    return rules

def _search_yara(matches, binary, constants, size=['fullword']):
    rules = _constants_to_rules(constants, size)
    for match in yara.compile(source=rules).match(data=binary):
        matches[match.meta['id']].add(match)

def _search_yara_xor(matches, binary, constants, xor_size=1):
    _binary = _xor_difference(binary, xor_size)
    _constants = []
    for constant in constants:
        if len(constant['value']) >= xor_size + 4:
            _constants.append({
                'name': constant['name'],
                'value': _xor_difference(constant['value'], xor_size)
            })

    _matches = defaultdict(Match)
    _search_yara(_matches, _binary, _constants, size=['fullword'])

    for _id, _match in _matches.items():
        values = []
        for _value in _match.values[0]:
            ori = constants[_id]['value']
            if _value.encoding == 'little':
                ori = ori[::-1]
            key = _xor(binary[_value.address:_value.address+len(_value.value)], ori)
            key = list(set(_cut(key, xor_size)))
            if len(key) == 1 and int.from_bytes(key[0], 'big') != 0:
                _value.value = ori
                matches[_id].values[0].append(_value)

def _distance(values):
    distances = [value.address for value in values]
    return max(distances) - min(distances)

def _auto_group(match):
    result = Result(match.name)

    for value in match.values[0]:
        result.groups.append(Group(0, [value]))

    for size in [8, 4]:
        values = match.values[size]
        values = sorted(values, key = lambda x: x.address)

        while values:
            # get the smallest distance group
            L, H, ans = 0, values[-1].address - values[0].address, None
            while L < H or (L == H and (not ans or values[ans[1]].address - values[ans[0]].address != L)):
                M = (L + H) >> 1
                slots = [0] * (match.length // size)
                head, tail, total = 0, -1, len(values)
                while head < total:
                    while tail < total - 1 and values[tail+1].address <= values[head].address + M:
                        tail += 1
                        slots[values[tail].index] += 1
                    if not 0 in slots:
                        ans, H = (head, tail), M
                        break
                    slots[values[head].index] -= 1
                    head += 1
                else:
                    L = M + 1

            # remove the selected group out of current values
            if ans:
                new_values, dels = [None] * (match.length // size), []
                for i in range(ans[1], ans[0] - 1, -1):
                    if not new_values[values[i].index]:
                        new_values[values[i].index] = values[i]
                        del values[i]
                # assume constants group won't be larger than 0x1000
                if _distance(new_values) <= 0x1000:
                    result.groups.append(Group(size, new_values))
            else:
                break

    if not result.groups:
        return None
        
    return result

def _remove_duplicate(result):
    seen, new_groups = [], []
    for group in result.groups:
        addresses = []
        for value in group.values:
            addresses += list(range(value.address, value.address + len(value.value)))
        if addresses not in seen:
            seen.append(addresses)
            new_groups.append(group)
    result.groups = new_groups

def _auto_groups(matches):
    results = []
    for match in matches.values():
        result = _auto_group(match)
        if result:
            _remove_duplicate(result)
            results.append(result)
    return results

def find_const(binary, constants, auto_group = True):
    matches = defaultdict(Match)
    _search_yara(matches, binary, constants, ['fullword', 'dword', 'qword'])
    for xor_size in range(1, 3):
        _search_yara_xor(matches, binary, constants, xor_size)
    results = _auto_groups(matches)
    return results
