from .CryFind import cryFindDB
from .CryptoAPI import cryptoAPIDB
from .KryptoAnalyzer import kryptoAnalyzerDB

def print_stats(dbs):
    print(f'''
Signature Database:
↳ {count_algo(dbs)} algorithm
↳ {count_constants(dbs)} constants''')

def count_algo(dbs):
    ans = 0
    for db in dbs:
        ans += len(db.constants.keys())
    return ans

def count_constants(dbs):
    ans = 0
    for db in dbs:
        for constants in db.constants.values():
            ans += len(constants)
    return ans

dbs = [cryFindDB, cryptoAPIDB, kryptoAnalyzerDB]
