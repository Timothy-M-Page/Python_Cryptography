from typing import Optional

ALPHABET = 'abcdefghijklmnopqrstuvwxyz'


def mod_inv(a: int) -> Optional[int]:
    # Inverse element in the group Z/len(alphabet)Z.
    mod = len(ALPHABET)
    for x in range(1, mod):
        if a*x % mod == 1:
            return x
    return None


def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    ciphertext = ''
    plaintext = plaintext.lower()
    for letter in plaintext:
        if letter in ALPHABET:
            # Replace each letter by ((a * letter.index) + b) mod len(alphabet).
            index = ALPHABET.index(letter)
            ciphertext += ALPHABET[(b + (a * index)) % len(ALPHABET)]
        else:
            ciphertext += letter
    return ciphertext


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    plaintext = ''
    inv = mod_inv(a)
    if inv is None:
        raise ValueError(f'Decryption failed due to no inverse for {a}.')
    for letter in ciphertext:
        if letter in ALPHABET:
            # Replace each letter by (letter.index - b) * mod_inv(a)
            index = ALPHABET.index(letter)
            plaintext += ALPHABET[((index - b) * inv) % len(ALPHABET)]
        else:
            plaintext += letter
    return plaintext
