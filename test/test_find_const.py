from crylib import find_const


def test_basic():
    results = find_const(b'abcd', [{'name': 'abcd', 'value': b'abcd'}])
    assert(len(results) == 1)


def test_summary():
    results = find_const(b'abcd', [{'name': 'abcd', 'value': b'abcd'}], summary=True)
    assert(len(results) == 1)


def test_xor():
    results = find_const(b'gdeb7452301>', [{'name': 'abcd', 'value': b'abcd12345678'}])
    assert(len(results) == 1)


def test_xor_2():
    results = find_const(b'adfeiv\t\x0b\x0b\rY[[]]__Qwreoij', [{'name': 'abcd', 'value': b'abcd12345678'}], xor_size_max=2)
    assert(len(results) == 1)


def test_complex():
    results = find_const(bytes.fromhex('44444444000044444444efeeeeeededddddd00000000333333330000'), [{'name': 'Winnti Custom Decoder', 'value': b'\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44'}])
    assert(len(results) == 1)
