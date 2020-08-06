class Value:
    def __init__(self, value, address, index, encoding, xor=b''):
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
        self.xor = xor

class Group:
    def __init__(self, blocksize, values):
        self.blocksize = blocksize
        self.values = values

class Result:
    def __init__(self, name):
        self.name = name
        self.groups = []
    def str(self, summary=False):
        output = ''
        output += f'[+] {self.name}\n'
        if not summary:
            for group in self.groups:
                output += '    - ' + {0: 'fullword', 8: 'qword', 4: 'dword'}[group.blocksize] + '\n'
                for value in group.values:
                    output += f'        | [{value.index}] {value.value.hex()} ({value.encoding})'
                    if value.xor:
                        output += f' (⊕ 0x{value.xor.hex()})'
                    output += f': 0x{value.address:x}\n'
        return output.strip('\n')

class Match:
    def __init__(self, match=None):
        self.values = {0: [], 8: [], 4: []}
        self.add(match)
    def add(self, match):
        if match:
            self.name = match.meta['name']
            self.length = match.meta['length']
            for address, varname, value in match.strings:
                _, size, index, encoding = varname.split('_')
                self.values[int(size)].append(Value(value, address, index, encoding))
