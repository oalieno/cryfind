import os
import yara
import pathlib
from ahocorapy.keywordtree import KeywordTree
from collections import defaultdict
from crylib import Constant, Result
from crylib.db import dbs
from crylib.db.CryptoAPI import apinames

try:
    import lief
except ImportError:
    lief = None

try:
    import pefile
except ImportError:
    pefile = None

assert lief or pefile

def _simple_valid_pefile(blob):
    '''
    Parameters
    ----------
    blob : bytes
        binary blob to be checked
    '''
    if blob[:2] != b'MZ' or len(blob) < 0x40:
        return False

    offset = int.from_bytes(blob[0x3c:0x3c+4], 'little')
    if offset + 4 > len(blob):
        return False

    return blob[offset:offset+4] == b'PE\0\0'

class Search:
    def __init__(self, filename):
        '''
        Parameters
        ----------
        filename : str
            the binary file need to analyze
        '''
        self.filename = filename
        self.binary = self._load_binary(filename)
        self.pe = None
        if _simple_valid_pefile(self.binary):
            self.pe = self._load_pe()

        self.methods = [
            #('Default CryFind DB', 'using literally string compare', self.search_constants),
            ('Yara-Rules Crypto Signatures', 'using yara rules in rules/ folder', self.search_yara),
            ('PE Import Table', 'search for known crypto api names in pe import table', self.search_pe_imports),
            ('Stackstrings', 'search for string made in runtime through pattern matching mov [rbp+??], ??', self.search_stackstrings)
        ]

    def _load_binary(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def _load_pe(self):
        if lief:
            try:
                return lief.PE.parse(raw=self.binary)
            except lief.exception:
                return None

        try:
            return pefile.PE(data=self.binary)
        except pefile.PEFormatError:
            return None

    @staticmethod
    def search_constant(binary, constant, lookup_table = None):
        '''
        find one constant.

        Parameters
        ----------
        binary : bytes
            the target binary to search for
        constant : Constant
            the constant instance to search for

        Returns
        -------
        Result
            Result instance of constant found in the binary. None if not found.
        '''
        addresses = []
        for value in constant.values:
            if lookup_table:
                if value in lookup_table:
                    addresses.append(lookup_table[value])
            else:
                if value in binary:
                    addresses.append(binary.find(value))
        if len(addresses) == len(constant.values):
            return Result(constant = constant, address = min(addresses))
        return None

    def search_constants(self):
        '''
        find constants using literally string compare. Constant database in crylib/db/ folder.

        Returns
        -------
        Dict[int, List[Result]]
            a dictionary with address as key, list of Result instances as value.
        '''
        results = defaultdict(list)

        kwtree = KeywordTree()
        for db in dbs:
            for constant in db.constants:
                for value in constant.values:
                    kwtree.add(value)
        kwtree.finalize()
        answer = list(kwtree.search_all(self.binary))
        table = {}
        for x in answer:
            if not table.get(x[0]):
                table[x[0]] = x[1]
            else:
                table[x[0]] = min(table[x[0]], x[1])

        for db in dbs:
            for constant in db.constants:
                result = self.search_constant(self.binary, constant, table)
                if result and str(result.constant) not in [str(r.constant) for r in results[result.address]]:
                    results[result.address].append(result)
        return results

    def search_yara(self):
        '''
        find constants using yara rules in rules/ folder.

        Returns
        -------
        Dict[int, List[Result]]
            a dictionary with address as key, list of Result instances as value.
        '''
        results = defaultdict(list)
        p = pathlib.Path(__file__).parent.parent
        for filename in p.glob('rules/*'):
            with open(str(filename)) as f:
                y = yara.compile(source = f.read())
            matches = y.match(data = self.binary)
            for match in matches:
                name, address, meta = match.rule, match.strings[0][0], match.meta
                if 'cryfind' in name:
                    constant = Constant(algorithm = meta['algorithm'], description = meta['description'])
                else:
                    constant = Constant(algorithm = name)
                result = Result(address = address, constant = constant)
                if result and str(result.constant) not in [str(r.constant) for r in results[result.address]]:
                    results[address].append(result)
        return results

    def search_pe_imports(self):
        '''
        search for known crypto api names in pe import table.

        Returns
        -------
        Dict[int, List[Result]]
            a dictionary with address as key, list of Result instances as value.
        '''
        if not self.pe:
            return {} # TODO: raise error or return None instead?

        results = defaultdict(list)
        imports = self._enum_imports_lief() if lief else \
                  self._enum_imports_pefile()
        for dllname, function in imports:
            for names in apinames.values():
                if function in names:
                    results[-1].append(Result(constant = Constant(description = f'{function.decode()} ({dllname.decode()})')))
        return results

    def _enum_imports_lief(self):
        for dll in self.pe.imports:
            # TODO: should use str for dll name and function name
            dllname = dll.name.lower().encode('latin1')
            for entry in dll.entries:
                if not entry.is_ordinal:
                    yield (dllname, entry.name.encode('latin1'))

    def _enum_imports_pefile(self):
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = dll.dll.lower()
            for entry in dll.imports:
                yield (dllname, entry.name)

    def search_stackstrings(self):
        '''
        search for string made in runtime through pattern matching mov [rbp+??], ??

        Returns
        -------
        Dict[int, List[Result]]
            a dictionary with address as key, list of Result instances as value.
        '''
        os.system(f'ida64 -A -S"ironstrings.py" -c {self.filename}') # command injection?
        with open('/tmp/stackstring-output', 'rb') as f:
            lines = f.readlines()
        stackstrings = b''
        indexes = []
        for line in lines:
            address = int(line.split(b' ')[0])
            string = line.strip().partition(b': ')[2][1:-1]
            stackstrings += string
            indexes += [address] * len(string)
        results = defaultdict(list)
        for db in dbs:
            for constant in db.constants:
                result = self.search_constant(stackstrings, constant)
                if result:
                    result.address = indexes[result.address]
                    if str(result.constant) not in [str(r.constant) for r in results[result.address]]:
                        results[result.address].append(result)
        return results

    def print_results(self, results_map):
        '''
        Parameters
        ----------
        results : Dict[int, List[Result]]
            a dictionary with address as key, list of Result instances as value.
        '''
        print()
        if results_map:
            for address, results in sorted(results_map.items()):
                if address >= 0:
                    print(f'[+] 0x{address:x}')
                    for i, result in enumerate(results):
                        constant = result.constant
                        text = '    '
                        if len(results) == 1:
                            text += '  '
                        elif i == 0:
                            text += '┌ '
                        elif i == len(results) - 1:
                            text += '└ '
                        else:
                            text += '│ '
                        text += str(constant)
                        print(text)
                else:
                    for result in results:
                        print(result.constant.description)

        else:
            print('[-] I found nothing')
        print()

    def run(self, exclude_methods=[]):
        '''
        run all search method and print the result summary
        '''
        for name, description, method in self.methods:
            if name in exclude_methods:
                continue

            print('=' * 30)
            print(name)
            print(f'↳ {description}')
            print('=' * 30)
            results = method()
            self.print_results(results)
