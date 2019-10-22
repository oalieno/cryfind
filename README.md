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
Default CryFind DB
↳ using literally string compare
==============================

[+] 0x5569
      ZIP2 - encryption
[+] 0x56b1
      ADLER_32
[+] 0x89fc
    ┌ RIJNDAEL - [S] [char]
    └ AES_forward_box
[+] 0x8afc
    ┌ RIJNDAEL - [S-inv] [char]
    └ AES_inverse_box
[+] 0x8bfc
    ┌ AES - TE0 Table
    │ RIJNDAEL - [T1]
    └ rijndael_te0
[+] 0x8ffc
    ┌ AES - TE1 Table
    └ rijndael_te1
[+] 0x93fc
      rijndael_te2
[+] 0x97fc
      rijndael_te3
[+] 0x9bfc
      rijndael_td0
[+] 0x9ffc
      rijndael_td1
[+] 0xa3fc
      rijndael_td2
[+] 0xa7fc
      rijndael_td3
[+] 0xce6c
      zinflate_lengthStarts
[+] 0xcee6
      zinflate_lengthExtraBits
[+] 0xcee8
      ZLIB_length_extra_bits
[+] 0xcf64
    ┌ zinflate_distanceStarts
    └ ZLIB_distance_starts
[+] 0xcfdc
    ┌ zinflate_distanceExtraBits
    └ ZLIB_distance_extra_bits
[+] 0xd054
    ┌ CRC32
    └ CRC32
[+] 0xd254
    ┌ CRC32 - [poly]
    └ CRC_32_Generator
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
Yara-Rules Crypto Signatures
↳ using yara rules in rules/ folder
==============================

[+] 0x89fc
    ┌ RijnDael_AES_CHAR
    └ RijnDael_AES_LONG
[+] 0x8bfc
      RijnDael_AES
[+] 0xd054
      CRC32_table
[+] 0xd254
      CRC32_poly_Constant

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

1. Literally string compare, including **crypto costants** and **crypto api name**
2. yara rules
3. **(PE executable only)** search **crypto api** name in pe import table 
4. Use [Flare-ida ironstrings](https://www.fireeye.com/blog/threat-research/2019/02/recovering-stackstrings-using-emulation-with-ironstrings.html) to search in stackstrings

## Database Resource

I merge the following crypto signatures into my database

* KryptoAnalyzer
    - http://www.dcs.fmph.uniba.sk/zri/6.prednaska/tools/PEiD/plugins/kanal.htm
* Polichombr
    - https://github.com/ANSSI-FR/polichombr/blob/dev/polichombr/analysis_tools/AnalyzeIt.rb#L26
* Yara Rules - crypto_signatures.yar
    - https://github.com/Yara-Rules/rules/blob/master/Crypto/crypto_signatures.yar
