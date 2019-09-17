from .CryFind import cryFindDB
from .CryptoAPI import cryptoAPIDB
from .KryptoAnalyzer import kryptoAnalyzerDB

def print_stats(dbs):
    print(f'''
Signature Database:
↳ {count_algo(dbs)} algorithm
↳ {count_constants(dbs)} constants''')

def print_db(title, url):
    text = f'\n{"-" * 30}\n'
    text += f'{title}\n'
    if url: text += f'↳ Refer to: {url}\n'
    text += f'{"-" * 30}'
    print(text)

def count_algo(dbs):
    ans = 0
    for db in dbs:
        ans += len(db.collections.keys())
    return ans

def count_constants(dbs):
    ans = 0
    for db in dbs:
        for collections in db.collections.values():
            ans += len(collections)
    return ans

dbs = [cryFindDB, cryptoAPIDB, kryptoAnalyzerDB]
