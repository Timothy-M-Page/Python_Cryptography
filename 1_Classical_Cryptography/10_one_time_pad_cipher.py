import os

ALPHABET = (' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]'
            '^_`abcdefghijklmnopqrstuvwxyz{|}~')


def one_time_pad_encrypt(plaintext: str, key: str):
    key_length = len(key)
    plaintext_length = len(plaintext)
    if plaintext_length != key_length:
        raise ValueError('Key length must match plaintext length.')
    ciphertext = ''
    index = 0
    for letter in plaintext:
        if letter in ALPHABET:
            a = ALPHABET.index(letter)
            b = ALPHABET.index(key[index])
            # Shift each letter by the corresponding key letter.
            ciphertext += ALPHABET[(a + b) % len(ALPHABET)]
            index += 1
        else:
            ciphertext += letter
    return ciphertext


def one_time_pad_decrypt(ciphertext: str, key: str):
    key_length = len(key)
    ciphertext_length = len(ciphertext)
    if ciphertext_length != key_length:
        raise ValueError('Key length must match ciphertext length.')
    plaintext = ''
    index = 0
    for letter in ciphertext:
        if letter in ALPHABET:
            a = ALPHABET.index(letter)
            b = ALPHABET.index(key[index])
            # Shift the letter back by the corresponding key letter.
            plaintext += ALPHABET[(a - b) % len(ALPHABET)]
            index += 1
        else:
            plaintext += letter
    return plaintext


def random_key(length: int):
    """
    A random key of given length may be generated using the operating
    system package to access hardware events, the randomness of which
    is cryptographically secure.
    """
    random_bytes = os.urandom(length)
    key = ''.join(ALPHABET[byte % len(ALPHABET)] for byte in random_bytes)
    return key
