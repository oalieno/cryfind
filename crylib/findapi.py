import yara

def _api_to_rule(name, functions, _ctr=[0]):
    _ctr[0] += 1

    rules = f'''rule api_{_ctr[0]} {{
    meta:
        name = "{name}"
    strings:
'''

    for i, function in enumerate(functions):
        rules += f'        $c{i} = "{function}"\n'

    rules += '''    condition:
        any of them
}
'''

    return rules


def _apis_to_rules(apis):
    rules = ''
    for api in apis:
        rules += _api_to_rule(api['name'], api['functions'])
    return rules

def find_api(binary, apis):
    '''Find crypto api names in binary

    Parameters
    ----------
    binary: bytes
        Target binary to search for.
    apis: List[Dict]
        API names you want to find.

    Returns
    -------
    List[Dict]

    Examples
    --------
    >>> results = find_api(b'......A_SHAFinal.....', [{'name': 'advapi32.dll', 'functions': ['A_SHAFinal', 'A_SHAInit']}])
    >>> print(results[0])
    {'name': 'advapi32.dll', 'functions': [{'name': 'A_SHAFinal', 'address': 6}]}
    '''
    rules = _apis_to_rules(apis)
    results = []
    for match in yara.compile(source=rules).match(data=binary):
        result = {'name': match.meta['name'], 'functions': []}
        for address, _, value in match.strings:
            result['functions'].append({'name': value.decode(), 'address': address})
        results.append(result)
    return results
