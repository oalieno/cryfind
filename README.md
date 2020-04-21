# cryfind

Search crypto signatures in binary

## Install

```
python setup.py install
```

## Usage

```
Usage: cryfind [-s SOURCES] [-m METHODS] [-c CONSTANTS] [-aexy] <filename>

-h --help           Show this screen
-s SOURCES          Sources to be searched, could be : plain,stackstrings or all [default: plain]
-m METHODS          Methods to be used, could be : string,yara,peimport or all [default: string]
-c CONSTANTS        Constants to be used, only for -m string, could be : crypto,apiname or all [default: crypto]
-a --all            Use all sources and methods and constants
-e --encode         Try various encoding method on constants, including big, little endian and two's complement
-x --xor            Bypass xor encryption with key length of one
-y --summary        Only show summary
```

```
Usage: crygen [-p PREFIX]

-h --help           Show this screen
-p PREFIX           Prefix of the generated yara rule name [default: cry]
```

## python API

```python
from crylib import *
from crylib.constants.CryptoConstants import constants as CryptoConstants
from crylib.constants.CryptoAPI import constants as CryptoAPIConstants

constants = CryptoConstants + CryptoAPIConstants

test = open('test', 'rb').read()
find_const(test, [
    {
        'name': 'test string 1', 'values': b'\xde\xad\xbe\xef',
        'name': 'test string 2', 'values': b'\xfa\xce\xb0\x0k\xab\xcd\x12\x34'
    }
], encode = True, xor = True)
find_const(stackstrings(test), constants)

rule = open('test.rules').read()
find_const_yara(test, rule)
```

## Sources

Sources to be searched.

* `plain` : Search in plain binary.
* `stackstrings` : Search in **stackstrings**, I use radare2 to emulate and extract the string from stack.

## Methods

* `string` : Literally string compare (using Aho–Corasick Algorithm)
* `yara` : Using yara rules. Downloaded from [crypto_signatures.yar](https://github.com/Yara-Rules/rules/blob/master/Crypto/crypto_signatures.yar)
* `peimport` : **(PE executable only)** search **crypto api name** in pe import table.

## Constants

Cryptographic constants, or you can also call it signatures or patterns.

* `crypto` : I merge the following crypto constants signatures into my database
    * KryptoAnalyzer
        - http://www.dcs.fmph.uniba.sk/zri/6.prednaska/tools/PEiD/plugins/kanal.htm
    * Polichombr
        - https://github.com/ANSSI-FR/polichombr/blob/dev/polichombr/analysis_tools/AnalyzeIt.rb#L26
* `apiname` : Crypto API Name, currently only contains Windows API.

## Options

* `encode` : Split constants into DWORD, QWORD and encode them as big, little, or two's complement.
* `xor` : Bypass xor encryption with key length of one. We implement custom algorithm to deal with this.
