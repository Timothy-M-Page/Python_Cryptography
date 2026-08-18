ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
SUB_ALPHABET = 'poiuytrewqasdfghjklmnbvcxz'


def sub_encrypt(plaintext: str, sub_alpha: str) -> str:
    plaintext = plaintext.lower()
    ciphertext = ''
    for letter in plaintext:
        if letter in ALPHABET:
            # Replace each letter by the corresponding letter in sub_alpha.
            ciphertext += sub_alpha[(ALPHABET.index(letter))]
        else:
            ciphertext += letter
    return ciphertext


def sub_decrypt(ciphertext: str, sub_alpha: str) -> str:
    plaintext = ''
    for letter in ciphertext:
        if letter in ALPHABET:
            # Replace each letter by the corresponding letter in the alphabet.
            plaintext += ALPHABET[(sub_alpha.index(letter))]
        else:
            plaintext += letter
    return plaintext
