from .DB import DB

data = [
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptCreateHash',
            'constants': [b'CryptCreateHash']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptGenKey',
            'constants': [b'CryptGenKey']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptDeriveKey',
            'constants': [b'CryptDeriveKey']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptHashData',
            'constants': [b'CryptHashData']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptEncrypt',
            'constants': [b'CryptEncrypt']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptDecrypt',
            'constants': [b'CryptDecrypt']
        }
    },
    {
        'algo': 'Crypto API',
        'collection': {
            'description': 'CryptGenRandom',
            'constants': [b'CryptGenRandom']
        }
    }
]

cryptoAPIDB = DB({
    'title': 'Crypto API Names',
    'url': ''
})
cryptoAPIDB.load(data)
