from .CryFind import cryFindDB
from .CryptoAPI import cryptoAPIDB
from .KryptoAnalyzer import kryptoAnalyzerDB
from .Polichombr import PolichombrDB

dbs = [cryFindDB, cryptoAPIDB, kryptoAnalyzerDB, PolichombrDB]

aliases = {
    ('zinflate_lengthStarts', ''): ('zinflate', 'lengthStarts'),
    ('zinflate_lengthExtraBits', ''): ('zinflate', 'lengthExtraBits'),
    ('ZLIB_length_extra_bits', ''): ('zinflate', 'lengthExtraBits'),
    ('zinflate_distanceStarts', ''): ('zinflate', 'distanceStarts'),
    ('ZLIB_distance_starts', ''): ('zinflate', 'distanceStarts'),
    ('zinflate_distanceExtraBits', ''): ('zinflate', 'distanceExtraBits'),
    ('ZLIB_distance_extra_bits', ''): ('zinflate', 'distanceExtraBits'),
    ('AES_forward_box', ''): ('AES', 'S-BOX'),
    ('RIJNDAEL', '[S] [char]'): ('AES', 'S-BOX'),
    ('AES_inverse_box', ''): ('AES', 'Inverse S-BOX'),
    ('RIJNDAEL', '[S-inv] [char]'): ('AES', 'Inverse S-BOX'),
    ('rijndael_te0', ''): ('AES', 'TE0 Table'),
    ('rijndael_te1', ''): ('AES', 'TE0 Table'),
    ('RIJNDAEL', '[T1]'): ('AES', 'TE0 Table'),
    ('rijndael_te2', ''): ('AES', 'TE2 Table'),
    ('rijndael_te3', ''): ('AES', 'TE3 Table'),
    ('rijndael_td0', ''): ('AES', 'TD0 Table'),
    ('rijndael_td1', ''): ('AES', 'TD1 Table'),
    ('rijndael_td2', ''): ('AES', 'TD2 Table'),
    ('rijndael_td3', ''): ('AES', 'TD3 Table'),
    ('CRC32', '[poly]'): ('CRC32', 'Polynomial'),
    ('CRC_32_Generator', ''): ('CRC32', 'Polynomial'),
    ('SHA256_K', ''): ('SHA-256', '[init]'),
    ('PKCS_sha512', ''): ('SHA-512', '[init]'),
    ('SHA224', 'Initial Hash Value'): ('SHA-224', '[Init]')
}

def filter(db):
    for constant in db.constants:
        c = (constant.algorithm, constant.description)
        constant.algorithm, constant.description = aliases.get(c, c)

for db in dbs:
    filter(db)
