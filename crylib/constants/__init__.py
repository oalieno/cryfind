#!/usr/bin/env python3
from .KryptoAnalyzer import constants as KryptoAnalyzerConstants
from .Polichombr import constants as PolichombrConstants
from .CryptoAPI import constants as CryptoAPIConstants

constants = []
constants += KryptoAnalyzerConstants
constants += PolichombrConstants
constants += CryptoAPIConstants

# Algorithm [Description]
aliases = {
    'AES [te0]': ['rijndael_te0', 'rijndael_te1', 'RIJNDAEL [T1]'],
    'AES [te2]': ['rijndael_te2'],
    'AES [te3]': ['rijndael_te3'],
    'AES [td0]': ['rijndael_td0'],
    'AES [td1]': ['rijndael_td1'],
    'AES [td2]': ['rijndael_td2'],
    'AES [td3]': ['rijndael_td3'],
    'AES [sbox]': ['RIJNDAEL [S] [char]', 'AES_forward_box'],
    'AES [inverse sbox]': ['RIJNDAEL [S-inv] [char]', 'AES_inverse_box'],
    'zinflate [lengthStarts]': ['zinflate_lengthStarts'],
    'zinflate [lengthExtraBits]': ['ZLIB_length_extra_bits', 'zinflate_lengthExtraBits'],
    'zinflate [distanceStarts]': ['ZLIB_distance_starts', 'zinflate_distanceStarts'],
    'zinflate [distanceExtraBits]': ['ZLIB_distance_extra_bits', 'zinflate_distanceExtraBits'],
    'CRC32': ['CRC32 [poly]', 'CRC_32_Generator'],
    'SHA256': ['SHA256_K'],
    'SHA512': ['PKCS_sha512']
}

lookup = {}
for alias, names in aliases.items():
    for name in names:
        lookup[name] = alias

for constant in constants:
    constant['name'] = lookup.get(constant['name'], constant['name'])