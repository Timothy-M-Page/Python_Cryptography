import hmac
from math import ceil

BLOCK_SIZE = 16

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D,
]

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

INV_MIX_COLUMNS_MATRIX = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]


irreducible_poly = 0x11B
irreducible_poly_128 = 0xe1000000000000000000000000000000
irreducible_poly_128_xts = 0x87


def multiply_by_x(element: int) -> int:
    """
    Multiply a polynomial by x, equivalent to shifting coefficients leftwards
    and replacing x**8 when necessary using the irreducible polynomial.
    """
    element <<= 1
    if element & 0x100:                  # if overflow beyond 8 bits
        element ^= irreducible_poly      # reduce by the irreducible polynomial
    return element & 0xFF


def multiply(element1: int, element2: int) -> int:
    """
    Multiply two elements together by adding x**n * element1
    everytime bit_n of element2 is 1.
    """
    result = 0
    for _ in range(8):
        if element2 & 1:
            result ^= element1
        element1 = multiply_by_x(element1)
        element2 >>= 1
    return result


def multiply_by_x_128(element: int) -> int:
    """
     Multiply a polynomial by x, equivalent to shifting coefficients rightwards
     and replacing x**128 when necessary using the irreducible polynomial.

     Note : Polynomials in GF(2**128) follow MSB notation.
     """
    if element & 1:
        return (element >> 1) ^ irreducible_poly_128
    else:
        return element >> 1


def multiply_128(element1: int, element2: int) -> int:
    """
    Multiply two elements in GF(2**128) together by adding x**n * element1
    everytime bit_n of element2 is 1.
    """
    result = 0
    for _ in range(128):
        if element2 & (1 << 127):
            result ^= element1

        element1 = multiply_by_x_128(element1)
        element2 <<= 1
        element2 &= (1 << 128) - 1

    return result


def matrix_multiply(matrix: list[list[int]], vector: list[int]) -> list[int]:
    """
    Ordinary multiplication of matrices with element multiplication and
    addition done in the Galois field GF(2**8).
    """
    output_vector = []
    for row in matrix:
        new_entry = 0
        for index in range(len(row)):
            new_entry ^= multiply(vector[index], row[index])
        output_vector.append(new_entry)
    return output_vector


def left_rotate(integer: int, shift: int, string_length: int) -> int:
    """
    Left rotation of an integer, right part captures the part
    that wraps around, which after masking combines to the correct length
    """
    left_part = (integer << (shift % string_length))
    right_part = (integer >> (string_length - shift % string_length))
    return (left_part | right_part) & ((1 << string_length) - 1)


def g(key_part: int, index: int) -> int:
    """
    A function used in the key schedule generation to add non-linearity.
    """
    shift = left_rotate(key_part, 8, 32)
    byte0 = SBOX[(shift >> 24) & 0xFF]
    byte1 = SBOX[(shift >> 16) & 0xFF]
    byte2 = SBOX[(shift >> 8) & 0xFF]
    byte3 = SBOX[shift & 0xFF]
    s_boxed = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3
    rc_xor = s_boxed ^ (RCON[index] << 24)
    return rc_xor


def h(key_part: int) -> int:
    """
    Another function used in the key schedule generation to add non-linearity.
    """
    byte0 = SBOX[(key_part >> 24) & 0xFF]
    byte1 = SBOX[(key_part >> 16) & 0xFF]
    byte2 = SBOX[(key_part >> 8) & 0xFF]
    byte3 = SBOX[key_part & 0xFF]
    s_boxed = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3
    return s_boxed


def key_schedule_round(word_array: list[int], key_length: int, round_num: int)\
        -> list[int]:
    """
    Creation of new words consists entirely of xor-ing previous words or
    xor-ing h or g of previous words. Where the function g and h are called
    depends on the length of key used.

    Words consist of 4 bytes, the number of original words is reduced_length.
    """

    reduced_length = (key_length // 4)
    word_array.append(word_array[-reduced_length] ^ g(word_array[-1], round_num))

    if key_length < 32:
        for _ in range(reduced_length - 1):
            word_array.append(word_array[-reduced_length] ^ word_array[-1])

    if key_length > 31:
        for _ in range((reduced_length // 2) - 1):
            word_array.append(word_array[-reduced_length] ^ word_array[-1])
        word_array.append(word_array[-reduced_length] ^ h(word_array[-1]))
        for _ in range((reduced_length // 2) - 1):
            word_array.append(word_array[-reduced_length] ^ word_array[-1])

    return word_array


def key_schedule_generation(key: bytes) -> list[int]:
    """
    Generation of the key schedule consists of applying the key schedule
    round as many times as necessary to compute the number of sub keys to match
    the number of AES rounds
    """

    key_length = len(key)
    key_int = int.from_bytes(key, byteorder='big')

    word_array = [(key_int >> shift) & 0xFFFFFFFF for shift
                  in range(8 * key_length - 32, -1, -32)]

    start_number_of_words = len(word_array)

    """
    Need number of AES rounds + 1 sub_keys, number of AES rounds
    is (key_length (bytes) / 4 + 6). Adding one and multiplying by 4
    to deduce the necessary number of words to generate gives:
    """

    end_number_of_words = key_length + 28
    number_of_rounds = ceil(end_number_of_words / start_number_of_words - 1)

    for index in range(number_of_rounds):
        word_array = key_schedule_round(word_array, key_length, index)

    word_array = word_array[:end_number_of_words]

    sub_keys = []
    for i in range(0, len(word_array), 4):
        subkey_bytes = b''.join(word.to_bytes(4, 'big')
                                for word in word_array[i:i + 4])
        sub_keys.append(int.from_bytes(subkey_bytes, 'big'))

    return sub_keys


def matrix_to_integer(matrix: list[list[int]]) -> int:
    """
    Concatenate entries of a matrix into an integer for later xor operation
    """
    flat = [matrix[row][col] for col in range(4) for row in range(4)]
    integers = [(byte << i) for byte, i in zip(flat, range(120, -1, -8))]
    output = 0
    for entry in integers:
        output |= entry
    return output


def s_box_substitution(state: bytes) -> list[list[int]]:
    """
    For every entry in the matrix, replace the entry as specified in the
    AES S-Box
    """
    state_matrix = []
    for index in range(4):
        row = []
        for index_2 in range(4):
            byte = state[index + 4 * index_2]
            row.append(int(SBOX[byte]))
        state_matrix.append(row)
    return state_matrix


def shift_row(state: list[list[int]]) -> list[list[int]]:
    """
    Shift row n left by n places.
    """
    return [row[i:] + row[:i] for i, row in enumerate(state)]


def mix_columns(state_matrix: list[list[int]]) -> list[list[int]]:
    """
    Multiply columns of the state_matrix by the transformation, then arrange
    these output vectors as the columns of a new matrix.
    """
    new_matrix = [[], [], [], []]
    for column in range(4):
        vector = [state_matrix[j][column] for j in range(4)]
        new_vector = matrix_multiply(MIX_COLUMNS_MATRIX, vector)
        for entry in range(4):
            new_matrix[entry].append(new_vector[entry])
    return new_matrix


def integer_to_matrix(integer: int) -> list[list[int]]:
    """
    During decryption the above matrix to integer function
    must be inverted.
    """
    state_bytes = integer.to_bytes(BLOCK_SIZE, byteorder='big')
    matrix = [[0] * 4 for _ in range(4)]
    index = 0
    for col in range(4):
        for row in range(4):
            matrix[row][col] = state_bytes[index]
            index += 1
    return matrix


def inverse_s_box_substitution(state_matrix: list[list[int]]) -> bytes:
    """
    For every entry in the matrix, replace the entry as specified in the
    AES Inverse S-Box to undo the s_box substitution that occurs
    during encryption.
    """
    matrix = []
    for row in state_matrix:
        new_row = [INV_SBOX[byte] for byte in row]
        matrix.append(new_row)
    byte_string = b''
    for col in range(4):
        for row in range(4):
            byte_string += matrix[row][col].to_bytes(1, 'big')
    return byte_string


def inverse_shift_row(state: list[list[int]]) -> list[list[int]]:
    """
    Shift row n right by n places.
    """
    return [row[-i:] + row[:-i] for i, row in enumerate(state)]


def inverse_mix_columns(state_matrix: list[list[int]]) -> list[list[int]]:
    """
    Multiply columns of the state_matrix by the  inverse transformation,
    then arrange these output vectors as the columns of a new matrix to
    undo the mix columns operation of encryption.
    """
    new_matrix = [[], [], [], []]
    for column in range(4):
        vector = [state_matrix[j][column] for j in range(4)]
        new_vector = matrix_multiply(INV_MIX_COLUMNS_MATRIX, vector)
        for entry in range(4):
            new_matrix[entry].append(new_vector[entry])
    return new_matrix


def zero_pad(plaintext: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Galois counter mode tags require padding with zeros to BLOCK_SIZE
    """
    length = len(plaintext)
    if length % BLOCK_SIZE == 0:
        pad_len = 0
    else:
        pad_len = block_size - (length % block_size)
    return plaintext + b'\x00' * pad_len


def aes_encryption_round(block: bytes, subkey: int, last_round: bool) -> bytes:
    """
    Combine the above encryption functions to create a round that occurs
    during AES encryption.
    """
    state = s_box_substitution(block)
    state = shift_row(state)
    if not last_round:
        state = mix_columns(state)
    state = matrix_to_integer(state)
    state = state ^ subkey
    state = state.to_bytes(BLOCK_SIZE, byteorder='big')
    return state


def aes_encrypt_block(block: bytes, key_schedule: list[int],
                      number_of_rounds: int) -> bytes:
    """
    Encryption of a block involves the repeated application of rounds,
    note that in the AES specification the last round does not involve
    the mix column operation.
    """

    state = int.from_bytes(block, byteorder='big') ^ key_schedule[0]
    state = state.to_bytes(BLOCK_SIZE, byteorder='big')

    for round_index in range(number_of_rounds - 1):
        state = aes_encryption_round(state, key_schedule[round_index + 1],
                                     False)

    state = aes_encryption_round(state, key_schedule[-1], True)
    return state


def calculate_gcm_tag(ciphertext: bytes, key_schedule: list[int], nonce: int,
                      additional_authentication_data: bytes,
                      number_of_rounds: int) -> bytes:
    """
    This function implements the GCM authentication step (GHASH + final
    counter encryption) to produce the 128-bit authentication tag.
    This function:

    1. Derives the hash subkey H = AES_K(0^128).
    2. Computes GHASH over additional authenticated data (AAD) and ciphertext.
    3. Appends the bit lengths of AAD and ciphertext to the GHASH input.
    4. Encrypts the pre-counter block J0 derived from the nonce.
    5. XORs the encrypted J0 with the GHASH result to produce the tag.
    """

    H = aes_encrypt_block(b'\x00' * BLOCK_SIZE, key_schedule, number_of_rounds)
    H_int = int.from_bytes(H, byteorder='big')

    acc = 0

    padded_aad = zero_pad(additional_authentication_data)
    aad_blocks = [padded_aad[i:i + BLOCK_SIZE] for i in range(0, len(padded_aad), BLOCK_SIZE)]

    for aad_block in aad_blocks:
        add_block_int = int.from_bytes(aad_block, byteorder='big')
        acc = multiply_128((acc ^ add_block_int), H_int)

    padded_ciphertext = zero_pad(ciphertext)
    blocks = [padded_ciphertext[i:i + BLOCK_SIZE]
              for i in range(0, len(padded_ciphertext), BLOCK_SIZE)]

    for cipher_block in blocks:
        cipher_block_int = int.from_bytes(cipher_block, byteorder='big')
        acc = multiply_128((acc ^ cipher_block_int), H_int)

    len_block = ((len(additional_authentication_data) * 8) << 64) | (len(ciphertext) * 8)

    acc = multiply_128((acc ^ len_block), H_int)

    J0 = ((nonce << 32) | 1).to_bytes(BLOCK_SIZE, 'big')
    J0_encrypted = aes_encrypt_block(J0, key_schedule, number_of_rounds)
    tag_int = int.from_bytes(J0_encrypted, 'big') ^ acc

    return tag_int.to_bytes(BLOCK_SIZE, 'big')


def aes_decryption_round(cipher_block: bytes, subkey: int, first_round: bool) -> bytes:
    """
    Applies the decryption functions in the reverse order to the encryption
    round with the last round now becoming the first round to skip the
    mix columns step.
    """
    state = int.from_bytes(cipher_block, byteorder='big')
    state ^= subkey
    state = integer_to_matrix(state)
    if not first_round:
        state = inverse_mix_columns(state)
    state = inverse_shift_row(state)
    state = inverse_s_box_substitution(state)
    return state


def aes_decrypt_block(block: bytes, key_schedule: list[int],
                      number_of_rounds: int) -> bytes:
    """
    Repeated application of the decryption round with the first round
    reversing the skipped mix columns step of the last round of the
    encrypt block function
    """
    state = aes_decryption_round(block, key_schedule[-1], True)

    for round_index in range(number_of_rounds - 1):
        state = aes_decryption_round(state, key_schedule[-round_index - 2],
                                     False)

    state = int.from_bytes(state, byteorder='big') ^ key_schedule[0]
    state = state.to_bytes(BLOCK_SIZE, byteorder='big')

    return state


def aes_encrypt_gcm(plaintext: bytes, key: bytes, nonce: bytes,
                    additional_authentication_data: bytes = b'') -> tuple[bytes, bytes]:
    """
    Galois Counter Mode uses Counter mode to encrypt plaintext and
    computes an authentication tag over the ciphertext and any additional
    authenticated data (AAD). The tag is verified during decryption to ensure
    the integrity and authenticity of the data.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be input as bytes.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be input as bytes.")
    if not isinstance(additional_authentication_data, bytes):
        raise TypeError("Additional_authentication_data must be bytes.")

    key_length = len(key)
    if key_length not in [16, 24, 32, 64]:
        raise ValueError("Key must be 16, 24, 32 or 64 bytes long.")

    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise TypeError("Nonce must be 12 bytes")

    nonce = int.from_bytes(nonce, byteorder='big')

    number_of_rounds = key_length // 4 + 6
    key_schedule = key_schedule_generation(key)

    blocks = [plaintext[i:i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]
    ciphertext = b''
    counter = 2

    for block in blocks:
        ctr_block = ((nonce << 32) | counter).to_bytes(BLOCK_SIZE, "big")
        key_stream = aes_encrypt_block(ctr_block, key_schedule, number_of_rounds)
        cipher_block = bytes(a ^ b for a, b in zip(block, key_stream))
        ciphertext += cipher_block
        counter += 1

    tag = calculate_gcm_tag(ciphertext, key_schedule, nonce,
                            additional_authentication_data, number_of_rounds)

    return ciphertext, tag


def aes_decrypt_gcm(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes,
                    additional_authentication_data: bytes = b'') -> bytes:
    """
    Galois Counter Mode uses Counter mode to encrypt plaintext and
    computes an authentication tag over the ciphertext and any additional
    authenticated data (AAD). The tag is verified during decryption to ensure
    the integrity and authenticity of the data.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be input as bytes.")
    if not isinstance(tag, bytes) or len(tag) != 16:
        raise ValueError("Tag must be 16 bytes.")
    if not isinstance(additional_authentication_data, bytes):
        raise TypeError("Additional authentication data must be bytes.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be input as bytes.")

    key_length = len(key)
    if key_length not in [16, 24, 32, 64]:
        raise ValueError("Key must be 16, 24, 32 or 64 bytes long.")

    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise TypeError("Nonce must be 12 bytes")

    nonce = int.from_bytes(nonce, byteorder='big')

    number_of_rounds = key_length // 4 + 6
    key_schedule = key_schedule_generation(key)

    tag_2 = calculate_gcm_tag(ciphertext, key_schedule, nonce,
                              additional_authentication_data, number_of_rounds)

    if not hmac.compare_digest(tag, tag_2):
        raise ValueError("Authentication failed, tags do not match.")

    plaintext = b''
    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    counter = 2

    for block in blocks:
        ctr_block = ((nonce << 32) | counter).to_bytes(BLOCK_SIZE, "big")
        key_stream = aes_encrypt_block(ctr_block, key_schedule, number_of_rounds)
        plaintext_block = bytes(a ^ b for a, b in zip(block, key_stream))
        plaintext += plaintext_block
        counter += 1

    return plaintext
