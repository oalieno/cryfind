from .constants.CryptoAPI import apis
try:
    import lief
except ImportError:
    pass


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
    if lief is None:
        raise ImportError('Install lief to use pe_import function : pip install lief')
    try:
        pe = lief.PE.parse(raw=list(binary))
    except lief.bad_format:
        raise ValueError('This is not PE binary')

    results = []
    for dllname, function in _enum_import(pe):
        for api in apis:
            if function in api['functions']:
                results.append({'dll': dllname, 'function': function})

    return results
