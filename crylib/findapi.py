import yara
from .base import Result, Value, Group

def _apiname_to_rule(dllname, funcnames, _ctr=[0]):
    _ctr[0] += 1

    rules = f'''rule api_{_ctr[0]} {{
    meta:
        name = "{dllname}"
    strings:
'''
    
    for i, funcname in enumerate(funcnames):
        rules += f'        $c{i} = "{funcname}"\n'

    rules += '''    condition:
        any of them
}
'''

    return rules


def _apinames_to_rules(apinames):
    rules = ''
    for dllname, funcnames in apinames.items():
        rules += _apiname_to_rule(dllname, funcnames)
    return rules

def find_api(binary, apinames):
    rules = _apinames_to_rules(apinames)
    results = []
    for match in yara.compile(source=rules).match(data=binary):
        result = Result(match.meta['name'])
        values = []
        for address, varname, value in match.strings:
            values.append(Value(value, address, 0, 0))
        result.groups.append(Group(0, values))
        results.append(result)
    return results
