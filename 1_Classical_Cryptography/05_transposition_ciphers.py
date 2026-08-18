import math


def transposition_encrypt(plaintext: str, permutation: list[int]) -> str:
    ciphertext = [''] * len(plaintext)
    for i in range(len(plaintext)):
        # Send each character to its permuted position.
        ciphertext[permutation[i]] = plaintext[i]
    return ''.join(ciphertext)


def transposition_decrypt(ciphertext: str, permutation: list[int]) -> str:
    plaintext = [''] * len(ciphertext)
    for i in range(len(ciphertext)):
        # Return the permuted characters to their original positions.
        plaintext[permutation.index(i)] = ciphertext[i]
    return ''.join(plaintext)


# Rail-Fence Cipher :


def index_to_row_map(i: int, k: int) -> int:
    """
    Each key defines a map f(i) : Z -> Z mod k, defining which row
    each index of the plaintext maps to, depending on the index mod 2(k-1).

    On a downwards diagonal the row is i mod k
    On an upwards diagonal the row reverses to k - (i mod k) - 2
    Hence, the map is defined mod 2(k-1), the full cycle length.
    """
    if k == 1:
        return 0
    if k > 1:
        mod = (i % (2 * (k - 1)))
        if mod in range(0, k):
            return mod
        if mod > k-1:
            mod2 = mod % k
            return k - mod2 - 2


def rail_fence_encrypt(plaintext: str, key: int) -> str:
    matrix = [['' for _ in range(len(plaintext))] for _ in range(key)]

    # Create the rail-fence pattern in a matrix using index_to_row_map.
    for index in range(len(plaintext)):
        matrix[index_to_row_map(index, key)][index] = plaintext[index]

    # Read the rows to form the ciphertext.
    ciphertext = ''
    for row in matrix:
        ciphertext += ''.join(row)
    return ciphertext


def rail_fence_decrypt(ciphertext: str, key: int) -> str:
    matrix = [['' for _ in range(len(ciphertext))] for _ in range(key)]

    # Create a matrix with the rail-fence pattern.
    for index in range(len(ciphertext)):
        matrix[index_to_row_map(index, key)][index] = 'x'

    # Fill the matrix to recreate the encryption pattern matrix.
    index = 0
    for i in range(key):
        for j in range(len(ciphertext)):
            if matrix[i][j] == 'x':
                matrix[i][j] = ciphertext[index]
                index += 1

    # Read diagonally to retrieve the plaintext.
    plaintext = ''
    for column in range(len(ciphertext)):
        for row in range(key):
            if matrix[row][column] != '':
                plaintext += matrix[row][column]
    return plaintext


# Columnar Transposition Cipher


def columnar_trans_encrypt(plaintext: str, permutation: list[int]) -> str:
    if set(permutation) != set(range(len(permutation))):
        raise ValueError('Permutation must be valid.')

    length = len(permutation)
    height = math.ceil(len(plaintext) / length)
    matrix = [['' for _ in range(length)] for _ in range(height)]

    # Fill a matrix with the plaintext.
    for index in range(len(plaintext)):
        matrix[index//length][index % length] = plaintext[index]

    # Read the matrix down the permuted rows to form the ciphertext.
    ciphertext = ''
    for column in range(length):
        for row in range(height):
            ciphertext += matrix[row][permutation.index(column)]
    return ciphertext


def columnar_trans_decrypt(ciphertext: str, permutation: list[int]) -> str:
    if set(permutation) != set(range(len(permutation))):
        raise ValueError('Permutation must be valid.')

    length = len(permutation)
    height = math.ceil(len(ciphertext) / length)
    inverse_permutation = sorted(range(length), key=lambda k: permutation[k])
    matrix = [['' for _ in range(length)] for _ in range(height)]

    # Remainder represents the number of empty entries on the last row.
    remainder = len(ciphertext) % length
    if remainder == 0:
        remainder = length

    # Recreate the encryption matrix.
    index = 0
    for col in inverse_permutation:
        if col < remainder:
            for row in range(height):
                if index < len(ciphertext):
                    matrix[row][col] = ciphertext[index]
                    index += 1
        # Enter nothing at the end a column where the last row was empty.
        if col >= remainder:
            for row in range(height - 1):
                if index < len(ciphertext):
                    matrix[row][col] = ciphertext[index]
                    index += 1

    # Read the rows to get the original plaintext.
    plaintext = ''.join(''.join(row) for row in matrix)
    return plaintext
