import os
import yara
import pefile
import pathlib
from collections import defaultdict
from crylib import Constant, Result
from crylib.db import dbs
from crylib.db.CryptoAPI import whitelist

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
        self.pe = self._load_pe(filename)

        self.methods = [
            ('Default CryFind DB', 'using literally string compare', self.search_constants),
            ('Yara-Rules Crypto Signatures', 'using yara rules in rules/ folder', self.search_yara),
            ('PE Import Table', 'search for known crypto api names in pe import table', self.search_pe_imports),
            ('Stackstrings', 'search for string made in runtime through pattern matching mov [rbp+??], ??', self.search_stackstrings)
        ]

    def _load_binary(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def _load_pe(self, filename):
        try:
            return pefile.PE(filename)
        except pefile.PEFormatError:
            return None

    @staticmethod
    def search_constant(binary, constant):
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
        for db in dbs:
            for constant in db.constants:
                result = self.search_constant(self.binary, constant)
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
            with open(filename) as f:
                y = yara.compile(source = f.read())
            matches = y.match(data = self.binary)
            for match in matches:
                algo, address = match.rule, match.strings[0][0]
                results[address].append(Result(address = address, constant = Constant(algorithm = algo)))
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
            return {}

        results = defaultdict(list)
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = dll.dll.lower()
            for value in dll.imports:
                for names in [*whitelist.values()]:
                    if value.name in names:
                        results[-1].append(Result(constant = Constant(description = f'{value.name.decode()} ({dllname.decode()})')))
        return results

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
            print(f'{name}')
            print(f'↳ {description}')
            print('=' * 30)
            results = method()
            self.print_results(results)
