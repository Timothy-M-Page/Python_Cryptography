import secrets

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

E = [
     32,  1,  2,  3,  4, 5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7]

FP = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25]


def s_boxes(index: int) -> list[list[int]]:
    if index == 0:
        return [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
    elif index == 1:
        return [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
    elif index == 2:
        return [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]
    elif index == 3:
        return [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]
    elif index == 4:
        return [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]
    elif index == 5:
        return [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]
    elif index == 6:
        return [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]
    elif index == 7:
        return [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]


def des_key_with_parity(key56_int: int) -> int:
    key_64 = 0
    for i in range(8):
        shift = (7 - i) * 7
        chunk = (key56_int >> shift) & 0x7F
        ones = chunk.bit_count()
        parity_bit = 1 if (ones % 2 == 0) else 0
        byte = (chunk << 1) | parity_bit
        key_64 = (key_64 << 8) | byte
    return key_64


def key_schedule(key64: int) -> list[int]:
    key56 = 0
    for pos in PC1:
        bit = (key64 >> (64 - pos)) & 1
        key56 = (key56 << 1) | bit

    sub_keys = []
    C = (key56 >> 28) & 0xFFFFFFF
    D = key56 & 0xFFFFFFF

    for i in range(16):
        if i in [0, 1, 8, 15]:
            shift_value = 1
        else:
            shift_value = 2

        C = ((C << shift_value) | (C >> (28 - shift_value))) & 0xFFFFFFF
        D = ((D << shift_value) | (D >> (28 - shift_value))) & 0xFFFFFFF
        CD = (C << 28) | D

        subkey = 0
        for x in PC2:
            bit = (CD >> (56 - x)) & 1
            subkey = (subkey << 1) | bit
        sub_keys.append(subkey)
    return sub_keys


def f_function(block_32: int, sub_key: int) -> int:
    block_48 = 0
    for pos in E:
        bit = (block_32 >> (32 - pos)) & 1
        block_48 = (block_48 << 1) | bit

    block48_xor = block_48 ^ sub_key

    sbox_inputs = []
    for i in range(8):
        shift = (7 - i) * 6
        six_bits = (block48_xor >> shift) & 0b111111
        sbox_inputs.append(six_bits)

    s_box_outputs = []

    for i in range(8):
        col = (sbox_inputs[i] >> 1) & 0b1111
        row = ((sbox_inputs[i] >> 5) << 1) | (sbox_inputs[i] & 1)
        s_box_outputs.append(s_boxes(i)[row][col])

    block48_xor_s_boxed = 0

    for i in range(8):
        block48_xor_s_boxed <<= 4
        block48_xor_s_boxed |= s_box_outputs[i] & 0b1111

    result = 0
    for pos in P:
        bit = (block48_xor_s_boxed >> (32 - pos)) & 1
        result = (result << 1) | bit

    return result


def des_encryption_round(block_64: int, sub_key: int) -> int:
    L = (block_64 >> 32) & 0xFFFFFFFF
    R = block_64 & 0xFFFFFFFF
    L_new = R
    R_new = L ^ f_function(R, sub_key)
    return ((L_new & 0xFFFFFFFF) << 32) | (R_new & 0xFFFFFFFF)


def des_encrypt(plaintext: bytes, key: int, pad: bool) -> bytes:

    if pad:
        pad_len = 8 - (len(plaintext) % 8)
        padded_data = plaintext + bytes([pad_len] * pad_len)
    else:
        padded_data = plaintext

    blocks = [padded_data[i:i+8] for i in range(0, len(padded_data), 8)]

    sub_keys = key_schedule(key)

    ciphertext = b""

    for block in blocks:
        block = int.from_bytes(block, "big")

        permuted_block = 0
        for pos in IP:
            bit = (block >> (64 - pos)) & 1
            permuted_block = (permuted_block << 1) | bit

        for i in range(16):
            permuted_block = des_encryption_round(permuted_block, sub_keys[i])

        L = (permuted_block >> 32) & 0xFFFFFFFF
        R = permuted_block & 0xFFFFFFFF
        permuted_block = (R << 32) | L

        permuted_block_2 = 0
        for pos in FP:
            bit = (permuted_block >> (64 - pos)) & 1
            permuted_block_2 = (permuted_block_2 << 1) | bit

        ciphertext += permuted_block_2.to_bytes(8, "big")

    return ciphertext


def des_decrypt(ciphertext: bytes, key: int, pad: bool) -> bytes:

    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]

    sub_keys = key_schedule(key)[::-1]

    plaintext = b""

    for block in blocks:
        block = int.from_bytes(block, "big")

        permuted_block = 0
        for pos in IP:
            bit = (block >> (64 - pos)) & 1
            permuted_block = (permuted_block << 1) | bit

        for i in range(16):
            permuted_block = des_encryption_round(permuted_block, sub_keys[i])

        L = (permuted_block >> 32) & 0xFFFFFFFF
        R = permuted_block & 0xFFFFFFFF
        permuted_block = (R << 32) | L

        permuted_block_2 = 0
        for pos in FP:
            bit = (permuted_block >> (64 - pos)) & 1
            permuted_block_2 = (permuted_block_2 << 1) | bit

        plaintext += permuted_block_2.to_bytes(8, "big")

    if pad:
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
    else:
        plaintext = plaintext

    return plaintext


def tdes_encrypt(plaintext: bytes, key: list[int]) -> bytes:
    ciphertext = des_encrypt(plaintext, key[0], True)
    ciphertext = des_decrypt(ciphertext, key[1], False)
    ciphertext = des_encrypt(ciphertext, key[2], False)
    return ciphertext


def tdes_decrypt(ciphertext: bytes, key: list[int]) -> bytes:
    plaintext = des_decrypt(ciphertext, key[2], False)
    plaintext = des_encrypt(plaintext, key[1], False)
    plaintext = des_decrypt(plaintext, key[0], True)
    return plaintext


def xor_bytes(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes((key.bit_length() + 7)//8, "big")
    rep_key = (key_bytes * ((len(data) // len(key_bytes)) + 1))[:len(data)]
    return bytes(d ^ k for d, k in zip(data, rep_key))


def des_x_encrypt(plaintext: bytes, key: list[int]) -> bytes:
    xor = xor_bytes(plaintext, key[1])
    encrypted = des_encrypt(xor, key[0], True)
    return xor_bytes(encrypted, key[2])


def des_x_decrypt(ciphertext: bytes, key: list[int]) -> bytes:
    xor = xor_bytes(ciphertext, key[2])
    decrypted = des_decrypt(xor, key[0], True)
    return xor_bytes(decrypted, key[1])


k1 = secrets.randbits(56)
k2 = des_key_with_parity(k1)
tdes_key = [secrets.randbits(56), secrets.randbits(56), secrets.randbits(56)]
