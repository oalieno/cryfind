# cryfind

Search crypto signatures in binary

## Install

TODO

## Usage

```
Usage: cryfind [-s SOURCES] [-m METHODS] [-a] <filename>

-h --help           Show this screen
-s SOURCES          Sources to be searched, could be : plain, stackstrings [default: plain]
-m METHODS          Methods to be used, could be : string, xor, yara, peimport [default: string,yara]
-a --all            Use all methods and sources
```

```
Usage: crygen [-p PREFIX]

-h --help           Show this screen
-p PREFIX           Prefix of the generated yara rule name [default: cry]
```

## python API

```python
from crylib import *
from crylib.constants import constants

test = open('test', 'rb').read()
find_const(test, [{'name': 'test string 1', 'values': [b'\xde\xad\xbe\xef']}])
find_const(stackstrings(test), constants, xor = True)

rule = open('test.rules').read()
find_const_yara(test, rule)
```

## Sources

1. `plain` : Search in plain binary.
2. `stackstrings` : Search in **stackstrings**, I use radare2 to emulate and extract the string from stack.

## Methods

I use the following methods to search crypto signatures

1. `string` : Literally string compare (using Aho–Corasick Algorithm), including **crypto costants** and **crypto api name**.
2. `xor` : Try all 256 possibililties to xor the binary before search.
3. `yara` : Using yara rules.
4. `peimport` : **(PE executable only)** search **crypto api name** in pe import table.

## TODO

2. pipenv
3. Dockerize the tools
4. Do dynamic analysis

## Constants Resource

I merge the following crypto constants signatures into my database

* KryptoAnalyzer
    - http://www.dcs.fmph.uniba.sk/zri/6.prednaska/tools/PEiD/plugins/kanal.htm
* Polichombr
    - https://github.com/ANSSI-FR/polichombr/blob/dev/polichombr/analysis_tools/AnalyzeIt.rb#L26
* Yara Rules - crypto_signatures.yar
    - https://github.com/Yara-Rules/rules/blob/master/Crypto/crypto_signatures.yar
