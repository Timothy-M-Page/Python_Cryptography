import secrets

key1 = secrets.randbits(80)

s_box = ["C", "5", "6", "B", "9", "0", "A", "D",
         "3", "E", "F", "8", "4", "7", "1", "2"]

p_box = [i*16 % 63 for i in range(63)] + [63]


def left_rotate(integer: int, shift: int, string_length: int) -> int:
    left = (integer << (shift % string_length))
    right = (integer >> (string_length - shift % string_length))
    return (left | right) & ((1 << string_length) - 1)


def key_schedule(key: int) -> list[int]:
    keys = []
    K = format(key, '080b')
    keys.append(int(K[:64], 2))
    counter = 1
    for i in range(31):
        K = int(K, 2)
        K = left_rotate(K, 61, 80)
        k_string = format(K, '080b')
        left_hex_bit = hex(int(k_string[:4], 2))[2:].upper()
        perm_hex_bit = s_box[int(left_hex_bit, 16)]
        permuted_k_string = format(int(perm_hex_bit, 16), '04b') + k_string[4:]
        five_bits = (permuted_k_string[60:65])
        xor_five_bits = format(int(five_bits, 2) ^ counter, '05b')
        K = permuted_k_string[0:60] + xor_five_bits + permuted_k_string[65:]
        keys.append(int(K[0:64], 2))
        counter += 1
    return keys


def present_encryption_round(plaintext: bytes, key: int) -> bytes:
    xor = int.from_bytes(plaintext, 'big') ^ key

    s_permutation = ""
    for i in range(16):
        nibble = (xor >> (4 * (15 - i))) & 0xF
        s_val = s_box[nibble]
        s_permutation += format(int(s_val, 16), '04b')

    p_perm = ['0'] * 64
    for i in range(64):
        p_perm[p_box[i]] = s_permutation[i]
    p_perm = ''.join(p_perm)

    return int(p_perm, 2).to_bytes((len(p_perm) + 7) // 8, 'big')


def present_decryption_round(ciphertext: bytes, key: int) -> bytes:
    xor = int.from_bytes(ciphertext, 'big') ^ key

    inverse_p_perm = ['0'] * 64
    for i in range(64):
        inverse_p_perm[i] = format(xor, '064b')[p_box[i]]
    inverse_p_perm = int(''.join(inverse_p_perm), 2)

    inverse_s_perm = ""
    for i in range(16):
        nibble = (inverse_p_perm >> (4 * (15 - i))) & 0xF
        s_val = [int(x, 16) for x in s_box].index(nibble)
        inverse_s_perm += format(s_val, '04b')

    return int(inverse_s_perm, 2).to_bytes((len(inverse_s_perm) + 7)
                                           // 8, 'big')


def present_encrypt(plaintext: bytes, key: int) -> bytes:

    if len(plaintext) % 8 == 0:
        pad_len = 0
    else:
        pad_len = 8 - (len(plaintext) % 8)
    plaintext += bytes([pad_len]) * pad_len

    blocks = [plaintext[i:i + 8] for i in range(0, len(plaintext), 8)]
    keys = key_schedule(key)
    ciphertext = b''
    for block in blocks:
        for i in range(31):
            block = present_encryption_round(block, keys[i])
        block = int.from_bytes(block, 'big') ^ keys[31]
        block = block.to_bytes(8, 'big')
        ciphertext += block
    return ciphertext


def present_decrypt(ciphertext: bytes, key: int) -> bytes:
    blocks = [ciphertext[i:i + 8] for i in range(0, len(ciphertext), 8)]
    keys = key_schedule(key)[::-1]
    plaintext = b''
    for block in blocks:
        for i in range(31):
            block = present_decryption_round(block, keys[i])
        block = (int.from_bytes(block, 'big')
                 ^ keys[31]).to_bytes(8, 'big')
        plaintext += block
    plaintext = plaintext[0:len(plaintext) - plaintext[-1]]
    return plaintext
