import yara
import struct
from collections import defaultdict, deque

def _cut(x, n):
    ans = []
    for i in range(0, len(x), n):
        ans.append(x[i:i+n])
    return ans

def _negative(value, c_type):
    value = struct.unpack(c_type, value)[0]
    return struct.pack(c_type, -value)

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

def _constant_to_rule(constant, size = 'fullword', _ctr = [0]):
    _ctr[0] += 1
    size = {
        'fullword': len(constant['value']),
        'dword': 4,
        'qword': 8
    }[size]
    
    values = _cut(constant['value'], size)
    
    rules = f'''rule cry_{_ctr[0]} {{
    meta:
        name = "{constant['name']}"
        length = "{len(values)}"
    strings:
'''
   
    for i, value in enumerate(values):
        for _id, encoding in _id_unique([
            value,
            value[::-1]
        ] + ([
            _negative(value, {4: 'i', 8: 'q'}[size])
        ] if size in [4, 8] else [])):
            rules += f'        $c_{i}_{_id} = {{ {encoding.hex()} }}\n'

    rules += f'''    condition:
        {' and '.join([f'(any of ($c_{i}_*))' for i in range(len(values))])}
}}
'''

    return rules

def _constants_to_rules(constants, size = 'fullword'):
    rules = ''
    for constant in constants:
        constant = {**constant, 'value': constant['value'][:64]}
        s = {
            'fullword': len(constant['value']),
            'dword': 4,
            'qword': 8
        }[size]
        if len(constant['value']) % s != 0:
            continue
        elif any([b'\x00' * 3 in value for value in _cut(constant['value'], s)]):
            continue
        rules += _constant_to_rule(constant, size)

    return rules

def _search_yara(binary, constants, size = 'fullword'):
    rules = _constants_to_rules(constants, size)
    results = []
    for match in yara.compile(source=rules).match(data=binary): 
        result = {
            'name': match.meta['name'],
            'length': int(match.meta['length']),
            'size': size,
            'values': [None] * int(match.meta['length'])
        }
        for address, varname, value in match.strings:
            _, index, encoding = varname.split('_')
            index = int(index)
            if result['values'][index]:
                result['values'][index]['addresses'].append(address)
            else:
                result['values'][index] = {
                    'value': value,
                    'encoding': [
                        'big',    # big endian
                        'little', # little endian
                        'neg'     # negative
                    ][int(encoding)],
                    'addresses': [address],
                    'index': index
                }
        results.append(result)
    return results

def _search_yara_xor(binary, constants, size = 'fullword', xor_size = 1):
    _binary = _xor_difference(binary, xor_size)
    _constants = []
    for constant in constants:
        if len(constant['value']) >= xor_size + 4:
            _constants.append({
                'name': constant['name'],
                'value': _xor_difference(constant['value'], xor_size)
            })
    _results = _search_yara(_binary, _constants)
    to_ori = {}
    for constant in constants:
        to_ori[constant['name']] = constant['value']
    results = []
    for _result in _results:
        result = {
            'name': _result['name'],
            'size': _result['size'],
            'values': []
        }
        for _value in _result['values']:
            addresses = []
            # filtering false positive cases
            for address in _value['addresses']:
                real = binary[address:address+len(_value['value'])]
                key = _xor(real, to_ori[_result['name']])
                key = set(_cut(key, xor_size))
                if len(key) == 1 and int.from_bytes(list(key)[0], 'big') != 0:
                    addresses.append(address)
            if addresses:
                result['values'].append({
                    'value': real,
                    'encoding': _value['encoding'],
                    'addresses': addresses,
                    'xor': list(key)[0].hex(),
                    'index': _value['index']
                })
        if result['values']:
            results.append(result)
    return results

def _auto_group(result):
    items = []
    for value in result['values']:
        for address in value['addresses']:
            items.append({
                **value,
                'addresses': [address]
            })
    items.sort(key = lambda x: x['addresses'][0])

    results = []

    # TODO: consider distances of address instead of index?
    while True:
        L, H, ans = 1, len(items), None
        while L < H or (L == H and (not ans or ans[1] != L)):
            M = (L + H) >> 1
            slots = [0] * len(result['values'])
            for i in range(M):
                slots[items[i]['index']] += 1
            for i in range(len(items) - M + 1):
                if all([slot > 0 for slot in slots]):
                    ans, H = (i, M), M
                    break
                if i + M < len(items):
                    slots[items[i]['index']] -= 1
                    slots[items[i+M]['index']] += 1
            else:
                L = M + 1

        if ans:
            values, dels, addresses = [None] * len(result['values']), [], []
            for i in range(ans[0], ans[0] + ans[1]):
                value = items[i]
                if not values[value['index']]:
                    values[value['index']] = value
                    dels.append(i)
                    addresses.append(value['addresses'][0])
            for i in dels[::-1]:
                del items[i]
            if max(addresses) - min(addresses) <= 0x1000:
                results.append({**result, 'values': values})
        else:
            break
        
    return results

def find_const(binary, constants, auto_group = True):
    results = []
    for size in ['fullword', 'dword', 'qword']:
        results += _search_yara(binary, constants, size)
    for xor_size in range(1, 3):
        results += _search_yara_xor(binary, constants, size, xor_size)
    if not auto_group:
        _results = []
        for result in results:
            grouped_results = _auto_group(result)
            if grouped_results:
                _results += grouped_results
        results = _results
    return results
