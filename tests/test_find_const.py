import pytest
from crylib import find_const

def test_basic():
    results = find_const(b'abcd', [{'name': 'abcd', 'value': b'abcd'}])
    assert(len(results) == 1)

def test_complex():
    results = find_const(bytes.fromhex('44444444000044444444efeeeeeededddddd00000000333333330000'), [{'name': 'Winnti Custom Decoder', 'value': b'\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44'}])
    assert(len(results) == 1)

