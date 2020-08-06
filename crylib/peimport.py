import lief
from .constants.CryptoAPI import apis

def _enum_import(pe):
    for dll in pe.imports:
        dllname = dll.name.lower()
        for entry in dll.entries:
            if not entry.is_ordinal:
                function = entry.name
                yield (dllname, function)

def pe_import(binary):
    '''Find api names in PE import tables

    Parameters
    ----------
    binary: bytes
        Target binary to search for.

    Returns
    -------
    List[Dict]

    Examples
    --------
    >>> results = pe_import(open('./test', 'wb').read())
    >>> print(results[0])
    {'dll': 'advapi32.dll', 'function': 'CryptAcquireContextA'}
    '''
    try:
        pe = lief.PE.parse(raw=list(binary))
    except lief.bad_format:
        raise Exception('[-] This is not PE binary')

    results = []
    for dllname, function in _enum_import(pe):
        for api in apis:
            if function in api['functions']:
                results.append({'dll': dllname, 'function': function})

    return results
