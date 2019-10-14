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
        self.bytes = self._load_bytes(filename)
        self.pe = self._load_pe(filename)

        self.methods = [
            ('Default CryFind DB', 'using literally string compare', self.search_constants),
            ('Yara-Rules Crypto Signatures', 'using yara rules in rules/ folder', self.search_yara),
            ('PE Import Table', 'search for known crypto api names in pe import table', self.search_pe_imports)
        ]

    def _load_bytes(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def _load_pe(self, filename):
        try:
            return pefile.PE(filename)
        except pefile.PEFormatError:
            return None

    def search_constant(self, constant):
        '''
        find one constant.

        Parameters
        ----------
        constant : Constant
            the constant instance to search for

        Returns
        -------
        List[int]
            addresses of constant found in the binary
        '''
        addresses = []
        for value in constant.values:
            if value in self.bytes:
                addresses.append(self.bytes.find(value))
        return addresses

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
                    addresses = self.search_constant(constant)
                    if len(addresses) == len(constant.values):
                        results[algo].append(Result(address = min(addresses), description = constant.description))
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
            matches = y.match(data = self.bytes)
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
            return {}, False

        results = defaultdict(list)
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = dll.dll.lower()
            for value in dll.imports:
                for names in [*whitelist.values()]:
                    if value.name in names:
                        results[value.name.decode()].append(Result(description = dllname.decode()))
        return results

    def print_results(self, results):
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
