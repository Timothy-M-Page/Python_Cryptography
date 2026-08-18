ALPHABET = 'abcdefghiklmnopqrstuvwxyz'
# j has been removed for the playfair cipher to construct a 5x5 key table.


def key_table(key: str) -> list[list[str]]:

    # Form the letters to place in a 5x5 grid.
    key = key.lower()
    key = key.replace(' ', '').replace('j', 'i')
    key_no_repeats = ''.join(sorted(set(key), key=key.index))
    rest_of_alphabet = ''.join(sorted(set(ALPHABET) - set(key_no_repeats)))
    table_letters = key_no_repeats + rest_of_alphabet

    # Place the letters row by row in a 5x5 matrix.
    matrix = [['' for _ in range(5)] for _ in range(5)]
    for i in range(0, 5):
        for j in range(0, 5):
            matrix[i][j] = table_letters[5*i + j]
    return matrix


def co_ordinates(entry: str, matrix: list[list[str]]) -> list[int]:
    # Return a letter's co-ordinates in a given matrix.
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] == entry:
                return [i, j]


def pair_map(letter1: str, letter2: str, matrix: list[list[str]]) -> str:
    # A map describing where each bi-gram is mapped to in the key table.
    c10 = co_ordinates(letter1, matrix)[0]
    c11 = co_ordinates(letter1, matrix)[1]
    c20 = co_ordinates(letter2, matrix)[0]
    c21 = co_ordinates(letter2, matrix)[1]
    if c10 == c20:
        return matrix[c10][(c11 + 1) % 5] + matrix[c20][(c21 + 1) % 5]
    if c11 == c21:
        return matrix[(c10 + 1) % 5][c11] + matrix[(c20 + 1) % 5][c21]
    else:
        return matrix[c10][c21] + matrix[c20][c11]


def inv_pair_map(letter1: str, letter2: str, matrix: list[list[str]]) -> str:
    # The inverse bi-gram mapping.
    c10 = co_ordinates(letter1, matrix)[0]
    c11 = co_ordinates(letter1, matrix)[1]
    c20 = co_ordinates(letter2, matrix)[0]
    c21 = co_ordinates(letter2, matrix)[1]
    if c10 == c20:
        return matrix[c10][(c11 - 1) % 5] + matrix[c20][(c21 - 1) % 5]
    if c11 == c21:
        return matrix[(c10 - 1) % 5][c11] + matrix[(c20 - 1) % 5][c21]
    else:
        return matrix[c10][c21] + matrix[c20][c11]


def playfair_encrypt(plaintext: str, key: str) -> str:
    plaintext = plaintext.lower().replace('j', 'i')
    plaintext = ''.join(char for char in plaintext if char.isalpha())

    # Choose a filler letter to replace double letters.
    FILLER1 = 'q'
    # Choose a second filler letter in case of a double q.
    FILLER2 = 'x'

    # Form the set of pairs to transform
    pairs = []
    i = 0
    while i < len(plaintext):
        # Repeated letters.
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            if plaintext[i] == FILLER1:
                pairs.append(FILLER1 + FILLER2)
            else:
                pairs.append(plaintext[i] + FILLER1)
            i += 1
        # Ordinary letters.
        else:
            pairs.append(plaintext[i:i + 2])
            i += 2

    # Add a filler letter at the end if len(plaintext) = odd.
    if len(pairs[-1]) == 1:
        pairs[-1] += FILLER1

    # For each pair form the ciphertext with the pair map.
    matrix = key_table(key)
    ciphertext = ''
    for i in pairs:
        ciphertext += pair_map(i[0], i[1], matrix)
    return ciphertext


def playfair_decrypt(ciphertext: str, key: str) -> str:
    FILLER1 = 'q'
    FILLER2 = 'x'

    # Split the ciphertext into pairs.
    pairs = [ciphertext[i:i + 2] for i in range(0, len(ciphertext), 2)]

    # Inverse transform every pair.
    decrypted_pairs = []
    for i in pairs:
        decrypted_pairs.append(inv_pair_map(i[0], i[1], key_table(key)))

    # Return filler letters back to their original repeated pairs.
    L = len(decrypted_pairs)
    for i in range(L):
        if (decrypted_pairs[i][1] == FILLER1 and i < (L - 1) and
                decrypted_pairs[i][0] == decrypted_pairs[i+1][0]):
            decrypted_pairs[i] = decrypted_pairs[i][0]
        if (decrypted_pairs[i] == FILLER1 + FILLER2 and i < (L - 1)
                and decrypted_pairs[i+1][0] == FILLER1):
            decrypted_pairs[i] = FILLER1
        if i == (L - 1) and decrypted_pairs[i][1] == FILLER1:
            decrypted_pairs[i] = decrypted_pairs[i][0]

    plaintext = ''.join(decrypted_pairs)
    return plaintext
