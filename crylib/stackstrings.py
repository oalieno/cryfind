import json
try:
    import r2pipe
except ImportError:
    pass


def thunked(blocks):
    for _, block in blocks.items():
        if block.get('jump') and blocks.get(block['jump']) is None:
            return True
    return False


def parse(output):
    data = b''
    for line in output.strip().split('\n')[1:]:
        data += int(line.split(' ')[1].strip(), 16).to_bytes(8, 'little')
    return data


def stack_dump(r):
    output = r.cmd('pxQ 0x00178000 - rsp @ rsp')
    return parse(output)


def _stackstrings(r, blocks, block, path, discovered):
    discovered.append(block)
    jump, fail = block.get('jump'), block.get('fail')

    data, leaf = b'', True
    for child in [jump, fail]:
        if child and blocks.get(child) and blocks[child] not in discovered:
            data += _stackstrings(r, blocks, blocks[child], path + [block], discovered)
            leaf = False
    if leaf:
        # initialize
        r.cmd('ar0')
        r.cmd('aeim')

        try:
            for p in path:
                # set rip
                r.cmd(f'aepc {p["addr"]}')

                write = 0
                for _ in range(p["ninstr"] - 1):
                    inst = json.loads(r.cmd('aoj @ rip'))[0]
                    # meomry write
                    if '=[' in inst["esil"]:
                        write += 1
                    # call
                    if 'rip,=' in inst["esil"]:
                        data += stack_dump(r)
                    r.cmd('aess')
                if write >= 5:
                    data += stack_dump(r)
        except:
            pass

    return data


def stackstrings(binary):
    '''Dump the stack from emulation

    Parameters
    ----------
    binary: bytes
        Target binary.

    Returns
    -------
    bytes
    '''
    if r2pipe is None:
        raise ImportError("Install r2pipe to use stackstrings function : pip install r2pipe")
    tmpfile = '/tmp/cryfind-tmp'
    with open(tmpfile, 'wb') as f:
        f.write(binary)

    r = r2pipe.open(tmpfile, flags=['-2'])
    r.cmd('aaa')
    functions = r.cmdj('aflqj')

    data = b''
    for function in functions:
        # get basic blocks table -> {0x01: block1, 0x06: block2, ...}
        blocks, root = {}, None
        for block in r.cmdj(f'abj {function}'):
            blocks[block['addr']] = block
            if root is None:
                root = block

        if thunked(blocks):
            continue

        data += _stackstrings(r, blocks, root, [], [])

    return data
