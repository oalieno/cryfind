import re
import yara
import pefile
import pathlib
from collections import defaultdict
from crylib import Result
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
            return Result(address = min(addresses), description = constant.description)
        return None

    def search_constants(self):
        '''
        find constants using literally string compare. Constant database in crylib/db/ folder.

        Returns
        -------
        Dict[str, List[Result]]
            a dictionary with algorithm name as key, list of Result instances as value.
        '''
        results = defaultdict(list)
        for db in dbs:
            for algo, constants in db.constants.items():
                for constant in constants:
                    result = self.search_constant(self.binary, constant)
                    if result:
                        results[algo].append(result)
        return results

    def search_yara(self):
        '''
        find constants using yara rules in rules/ folder.

        Returns
        -------
        Dict[str, List[Result]]
            a dictionary with algorithm name as key, list of Result instances as value.
        '''
        results = defaultdict(list)
        p = pathlib.Path(__file__).parent.parent
        for filename in p.glob('rules/*'):
            with open(filename) as f:
                y = yara.compile(source = f.read())
            matches = y.match(data = self.binary)
            for match in matches:
                algo, address = match.rule, match.strings[0][0]
                results[algo].append(Result(address = address))
        return results

    def search_pe_imports(self):
        '''
        search for known crypto api names in pe import table.

        Returns
        -------
        Dict[str, List[Result]]
            a dictionary with algorithm name as key, list of Result instances as value.
        '''
        if not self.pe:
            return {}

        results = defaultdict(list)
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = dll.dll.lower()
            for value in dll.imports:
                for names in [*whitelist.values()]:
                    if value.name in names:
                        results[value.name.decode()].append(Result(description = dllname.decode()))
        return results

    def search_stackstrings(self):
        '''
        search for string made in runtime through pattern matching mov [rbp+??], ??

        Returns
        -------
        Dict[str, List[Result]]
            a dictionary with algorithm name as key, list of Result instances as value.
        '''
        stackstrings = b''.join(re.findall(b'\xc6\x45.(.)', self.binary))
        results = defaultdict(list)
        for db in dbs:
            for algo, constants in db.constants.items():
                for constant in constants:
                    result = self.search_constant(stackstrings, constant)
                    if result:
                        results[algo].append(result)
        return results

    def print_results(self, results):
        '''
        Parameters
        ----------
        results : Dict[str, List[Result]]
            a dictionary with algorithm name as key, list of Result instances as value.
        '''
        print()
        if results:
            for algo, constants in results.items():
                print(f'[+] {algo}')
                for constant in constants:
                    if constant.address >= 0:
                        print(f'      Address: 0x{constant.address:x}')
                    if constant.description:
                        print(f'      ↳ Description: {constant.description}')

        else:
            print('[-] I found nothing')
        print()

    def run(self):
        '''
        run all search method and print the result summary
        '''
        for name, description, method in self.methods:
            print('=' * 30)
            print(f'{name}')
            print(f'↳ {description}')
            print('=' * 30)
            results = method()
            self.print_results(results)
