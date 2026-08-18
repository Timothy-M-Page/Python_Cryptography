import math

"""
The objective of this file is to extend a small piece of key material
into a sufficiently long key to allow the application of a OTP.

However, the problems are a way to be able to do so that introduces more
entropy than the original key material.
"""

def to_base(n: int, base: int) -> str:
    if not (2 <= base <= 9):
        raise ValueError("Base must be between 2 and 9")
    result = ""
    while n > 0:
        n, rem = divmod(n, base)
        result = str(rem) + result
    return result


def adjoin_base(number: int, base: int) -> int:
    string_number = str(number)
    base_number = str(to_base(number, base))
    flipped_base_number = ""
    counter = 0
    for digit in base_number:       # Can easily strengthen this condition
        if counter % 2 == 0:        # E.g flip if digit
            flipped_base_number += digit
        if counter % 2 == 1:
            flipped_base_number += str(9 - int(digit))
        counter += 1
    return int(string_number + flipped_base_number)


def key_extension(key: int, length: int) -> int:
    for index in range(length):
        if int(str(key)[index]) > 4:
            base = int(str(key)[index])
        else:
            base = 9 - int(str(key)[index])
        key = adjoin_base(key, base)
    return int(key)


def extended_otp_encrypt(plaintext: bytes, key: int) -> bytes:
    L = len(plaintext) * 8
    K = key.bit_length()
    length = math.ceil(math.log2(L/K))
    extended_key = key_extension(key, length)
    extended_key = int((str(extended_key)[::-1]))
    print(extended_key)
    xor = int.from_bytes(plaintext, byteorder="big") ^ extended_key
    mask = (1 << (len(plaintext) * 8)) - 1
    xor &= mask
    return xor.to_bytes(len(plaintext), "big")


def extended_otp_decrypt(ciphertext: bytes, key: int) -> bytes:
    L = len(ciphertext) * 8
    K = key.bit_length()
    length = math.ceil(math.log2(L/K))
    extended_key = key_extension(key, length)
    extended_key = int(str(extended_key)[::-1])
    print(extended_key)
    xor = int.from_bytes(ciphertext, byteorder="big") ^ extended_key
    mask = (1 << (len(ciphertext) * 8)) - 1
    xor &= mask
    return xor.to_bytes(len(ciphertext), "big")
