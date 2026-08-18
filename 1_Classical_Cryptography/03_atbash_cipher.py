ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

# Atbash is its own inverse, hence encryption and decryption are the same.


def atbash(plaintext: str) -> str:
    ciphertext = ''
    plaintext = plaintext.lower()
    for letter in plaintext:
        if letter in ALPHABET:
            # Replace each letter by its reflection in the alphabet.
            ciphertext += ALPHABET[25 - ALPHABET.index(letter)]
        else:
            ciphertext += letter
    return ciphertext
