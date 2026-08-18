ALPHABET = 'abcdefghijklmnopqrstuvwxyz'


def caesar_encrypt(plaintext: str, key: int) -> str:
    plaintext = plaintext.lower()
    ciphertext = ''
    for letter in plaintext:
        if letter in ALPHABET:
            # Shift each letter by 'key' places.
            ciphertext += ALPHABET[(ALPHABET.index(letter) + key)
                                   % len(ALPHABET)]
        else:
            ciphertext += letter
    return ciphertext


def caesar_decrypt(ciphertext: str, key: int) -> str:
    plaintext = ''
    for letter in ciphertext:
        if letter in ALPHABET:
            # Shift the letter back by 'key' places.
            plaintext += ALPHABET[(ALPHABET.index(letter) - key)
                                  % len(ALPHABET)]
        else:
            plaintext += letter
    return plaintext

print(caesar_encrypt("hello", 5))
