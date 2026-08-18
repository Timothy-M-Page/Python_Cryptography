ALPHABET = (' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]'
            '^_`abcdefghijklmnopqrstuvwxyz{|}~')


def autokey_encrypt(plaintext: str, key: str) -> str:
    ciphertext = ''
    # Form the autokey by adjoining the plaintext to the key.
    key += plaintext
    index = 0
    for letter in plaintext:
        if letter in ALPHABET:
            a = ALPHABET.index(letter)
            b = ALPHABET.index(key[index % len(key)])
            # Shift each letter by the corresponding key letter.
            ciphertext += ALPHABET[(a+b) % len(ALPHABET)]
            index += 1
        else:
            ciphertext += letter
    return ciphertext


def autokey_decrypt(ciphertext: str, key: str) -> str:
    plaintext = ''
    index = 0
    for letter in ciphertext:
        if letter in ALPHABET:
            a = ALPHABET.index(letter)
            b = ALPHABET.index(key[index % len(key)])
            # Shift the letter back by the corresponding key letter.
            plaintext += ALPHABET[(a-b) % len(ALPHABET)]
            # Reconstruct the key by iteratively adding each decrypted letter.
            key += plaintext[index]
            index += 1
        else:
            plaintext += letter
    return plaintext
