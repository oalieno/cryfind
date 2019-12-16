# cryfind

Search crypto signatures in binary

## Install

TODO

## Usage

```
./cryfind.py [-l VALUE] <filename>
```

## Example

```
./cryfind.py WannaCry
```

```
==============================
Yara-Rules Crypto Signatures
↳ using yara rules in rules/ folder
==============================

[+] 0x56b1
      ADLER_32
[+] 0x683e
      ZIP2 - encryption
[+] 0x89fc
    ┌ RijnDael_AES_CHAR
    │ RijnDael_AES_LONG
    └ AES - S-BOX
[+] 0x8afc
      AES - Inverse S-BOX
[+] 0x8bfc
    ┌ RijnDael_AES
    └ AES - TE0 Table
[+] 0x8ffc
    ┌ AES - TE1 Table
    └ AES - TE0 Table
[+] 0x93fc
      AES - TE2 Table
[+] 0x97fc
      AES - TE3 Table
[+] 0x9bfc
      AES - TD0 Table
[+] 0x9ffc
      AES - TD1 Table
[+] 0xa3fc
      AES - TD2 Table
[+] 0xa7fc
      AES - TD3 Table
[+] 0xce6c
      zinflate - lengthStarts
[+] 0xcee8
      zinflate - lengthExtraBits
[+] 0xcf64
      zinflate - distanceStarts
[+] 0xcfdc
      zinflate - distanceExtraBits
[+] 0xd054
    ┌ CRC32_table
    └ CRC32
[+] 0xd254
    ┌ CRC32_poly_Constant
    └ CRC32 - Polynomial
[+] 0xdc16
      Crypto API - CryptReleaseContext (advapi32.dll)
[+] 0xf0c4
      Crypto API - CryptGenKey (advapi32.dll)
[+] 0xf0d0
      Crypto API - CryptDecrypt (advapi32.dll)
[+] 0xf0e0
      Crypto API - CryptEncrypt (advapi32.dll)
[+] 0xf0f0
      Crypto API - CryptDestroyKey (advapi32.dll)
[+] 0xf100
      Crypto API - CryptImportKey (advapi32.dll)
[+] 0xf110
      Crypto API - CryptAcquireContextA (advapi32.dll)
[+] 0x1e4483
      Crypto API - MD5 (libeay32.dll)

==============================
PE Import Table
↳ search for known crypto api names in pe import table
==============================

CryptReleaseContext (advapi32.dll)
```

## python API

```python
from crylib.search import Search

s = Search('./binary')

results = s.search_constants()
results = s.search_yara()
results = s.search_pe_imports()
results = s.search_stackstrings()

s.print_results(results)

s.run() # run all above methods and print results
```

## Methods

I use the following methods to search crypto signatures

1. Literally string compare (using Aho–Corasick Algorithm), including **crypto costants** and **crypto api name**. This method is off by default. All Constants are in yara rules directory now. Use `./cryfind.py -g` to generate yara rules.
2. yara rules
3. **(PE executable only)** search **crypto api** name in pe import table 
4. Use [Flare-ida ironstrings](https://www.fireeye.com/blog/threat-research/2019/02/recovering-stackstrings-using-emulation-with-ironstrings.html) to search in stackstrings

## TODO

1. Migrate Flare-ida ironstrings from IDA to Ghidra
2. Do dynamic analysis

## Database Resource

I merge the following crypto signatures into my database

* KryptoAnalyzer
    - http://www.dcs.fmph.uniba.sk/zri/6.prednaska/tools/PEiD/plugins/kanal.htm
* Polichombr
    - https://github.com/ANSSI-FR/polichombr/blob/dev/polichombr/analysis_tools/AnalyzeIt.rb#L26
* Yara Rules - crypto_signatures.yar
    - https://github.com/Yara-Rules/rules/blob/master/Crypto/crypto_signatures.yar
