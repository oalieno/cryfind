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
        self.values = {0: [], 8: [], 4: []}
        self.add(match)
    def add(self, match):
        if match:
            self.name = match.meta['name']
            self.length = match.meta['length']
            for address, varname, value in match.strings:
                _, size, index, encoding = varname.split('_')
                self.values[int(size)].append(Value(value, address, index, encoding))
