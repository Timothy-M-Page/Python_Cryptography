ALPHABET = (' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]'
            '^_`abcdefghijklmnopqrstuvwxyz{|}~')


def vigenere_encrypt(plaintext: str, key: str) -> str:
    plaintext = plaintext.lower()
    ciphertext = ''
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


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    plaintext = ''
    index = 0
    for letter in ciphertext:
        if letter in ALPHABET:
            a = ALPHABET.index(letter)
            b = ALPHABET.index(key[index % len(key)])
            # Shift the letter back by the corresponding key letter.
            plaintext += ALPHABET[(a-b) % len(ALPHABET)]
            index += 1
        else:
            plaintext += letter
    return plaintext
