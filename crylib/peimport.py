import lief
from .constants.CryptoAPI import apinames

def _enum_import(pe):
    for dll in pe.imports:
        dllname = dll.name.lower()
        for entry in dll.entries:
            if not entry.is_ordinal:
                function = entry.name
                yield (dllname, function)

def pe_import(binary):
    try:
        pe = lief.PE.parse(raw = list(binary))
    except:
        return []
    
    results = []
    for dllname, function in _enum_import(pe):
        for names in apinames.values():
            if function in names:
                results.append({'dll': dllname, 'function': function})
    
    return results
