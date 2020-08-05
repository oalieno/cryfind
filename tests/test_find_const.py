import pytest
from crylib import *

def test_find_const():
    results = find_const(b'abcd', [{'name': 'abcd', 'value': b'abcd'}])
    assert(len(results) == 1)
    results = find_const(bytes.fromhex('44444444000044444444efeeeeeededddddd00000000333333330000'), [{'name': 'Winnti Custom Decoder', 'value': b'\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44'}])
    assert(len(results) == 1)

