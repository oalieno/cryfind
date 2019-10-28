from .CryFind import cryFindDB
from .CryptoAPI import cryptoAPIDB
from .KryptoAnalyzer import kryptoAnalyzerDB
from .Polichombr import PolichombrDB

dbs = [cryFindDB, cryptoAPIDB, kryptoAnalyzerDB, PolichombrDB]

aliases = {
    ('zinflate', 'lengthStarts'): [('zinflate_lengthStarts', '')],
    ('zinflate', 'lengthExtraBits'): [('zinflate_lengthExtraBits', ''), ('ZLIB_length_extra_bits', '')],
    ('zinflate', 'distanceStarts'): [('zinflate_distanceStarts', ''), ('ZLIB_distance_starts', '')],
    ('zinflate', 'distanceExtraBits'): [('zinflate_distanceExtraBits', ''), ('ZLIB_distance_extra_bits', '')],
    ('AES', 'S-BOX'): [('AES_forward_box', ''), ('RIJNDAEL', '[S] [char]')],
    ('AES', 'Inverse S-BOX'): [('AES_inverse_box', ''), ('RIJNDAEL', '[S-inv] [char]')],
    ('AES', 'TE0 Table'): [('rijndael_te0', '')],
    ('AES', 'TE1 Table'): [('rijndael_te1', ''), ('RIJNDAEL', '[T1]')],
    ('AES', 'TE2 Table'): [('rijndael_te2', '')],
    ('AES', 'TE3 Table'): [('rijndael_te3', '')],
    ('AES', 'TD0 Table'): [('rijndael_td0', '')],
    ('AES', 'TD1 Table'): [('rijndael_td1', '')],
    ('AES', 'TD2 Table'): [('rijndael_td2', '')],
    ('AES', 'TD3 Table'): [('rijndael_td3', '')],
    ('CRC32', 'Polynomial'): [('CRC32', '[poly]'), ('CRC_32_Generator', '')],
    ('SHA-256', '[init]'): [('SHA256_K', '')],
    ('SHA-512', '[init]'): [('PKCS_sha512', '')],
    ('SHA-224', '[Init]'): [('SHA224', 'Initial Hash Value')]
}

def filter(db):
    for constant in db.constants:
        for key, values in aliases.items():
            for value in values:
                if value == (constant.algorithm, constant.description):
                    constant.algorithm, constant.description = key

for db in dbs:
    filter(db)
