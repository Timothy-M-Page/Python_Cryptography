import numpy as np
from typing import List

"""
For levels of security comparable to AES-128 and AES-256 degrees of 
512 and 1024 are required. Such polynomials are implemented in the 
NEW_HOPE-512 and NEW_HOPE-1024 algorithms with a modulus of 12289.
"""


class CyclotomicRing:
    """
    ℤ_q[x] / (x^n + 1)
    Cyclotomic polynomials provide a simple reduction
    due to x**n = -1 mod (x**n +1) meaning x**(n+j) --> -x**j.
    """

    def __init__(self, modulus: int, degree: int):
        self.modulus = modulus
        self.degree = degree

    def add(self, poly1: List[int], poly2: List[int]) -> List[int]:
        return [(x + y) % self.modulus for x, y in zip(poly1, poly2)]

    def subtract(self, poly1: List[int], poly2: List[int]) -> List[int]:
        return [(x - y) % self.modulus for x, y in zip(poly1, poly2)]

    def multiply(self, poly1: List[int], poly2: List[int]) -> List[int]:
        result = [0] * self.degree
        for i in range(self.degree):
            for j in range(self.degree):
                k = (i + j) % self.degree
                sign = -1 if i + j >= self.degree else 1
                result[k] = (result[k] + poly1[i] * poly2[j] * sign) % self.modulus
        return result


def generate_keys(modulus: int, degree: int, fidelity: int):
    """
    The fidelity is the maximum distance from the modulus of the entries in
    certain polynomials.
    The RLWS crypto-system only functions if error_poly, secret_poly and
    auxiliary_error polynomials contain values close to the modulus.
    """
    ring = CyclotomicRing(modulus, degree)

    polynomial = np.random.randint(0, modulus, size=degree).tolist()
    error_poly = np.random.randint(-fidelity, fidelity, size=degree).tolist()
    secret_poly = np.random.randint(-fidelity, fidelity, size=degree).tolist()

    target = ring.add(ring.multiply(polynomial, secret_poly), error_poly)

    public_key = (target, polynomial)
    private_key = secret_poly

    return public_key, private_key


def generate_auxiliary_error_polynomials(degree: int, fidelity: int) -> list:
    return [np.random.randint(-fidelity, fidelity + 1, size=degree) for _ in range(3)]


def encode_message_to_poly_and_block(message: bytes, modulus: int, degree: int) -> list[list[int]]:

    bit_list = [int(b) for b in ''.join(f'{byte:08b}' for byte in message)]

    if (len(bit_list) % degree) != 0:
        bit_list = bit_list + [0] * (degree - (len(bit_list) % degree))

    half_modulus = modulus // 2
    encoded_bit_list = [half_modulus if bit == 1 else 0 for bit in bit_list]

    blocks = [encoded_bit_list[i:i + degree] for i in
              range(0, len(encoded_bit_list), degree)]

    return blocks


def decode_blocks_to_message(blocks: list[list[int]], modulus: int) -> bytes:
    threshold = modulus // 4

    bit_string = "".join("1" if threshold <= co_eff <= 3 * threshold else "0"
                         for poly in blocks for co_eff in poly)

    byte_array = bytearray(int(bit_string[i:i + 8], 2)
                           for i in range(0, len(bit_string), 8))

    return bytes(byte_array)


def rlws_encrypt(plaintext: bytes, public_key: tuple, auxiliary_errors: list,
                 modulus: int, degree: int) -> list[list[list[int]]]:

    ring = CyclotomicRing(modulus, degree)
    blocks = encode_message_to_poly_and_block(plaintext, modulus, degree)
    cipher_blocks = []

    for poly in blocks:
        u = ring.add(ring.multiply(public_key[1], auxiliary_errors[0]), auxiliary_errors[1])
        v = ring.add(ring.multiply(public_key[0], auxiliary_errors[0]), auxiliary_errors[2])
        v = ring.add(v, poly)
        cipher_blocks.append([u, v])

    return cipher_blocks


def rlws_decrypt(cipher_blocks: list[list[list[int]]], private_key: list[int], modulus: int, degree: int) -> bytes:
    ring = CyclotomicRing(modulus, degree)
    decoded_blocks = []

    for cipher_block in cipher_blocks:
        encoded_plaintext = ring.subtract(cipher_block[1], ring.multiply(cipher_block[0], private_key))
        decoded_blocks.append(encoded_plaintext)

    return decode_blocks_to_message(decoded_blocks, modulus).rstrip(b'\x00')


MODULUS = 12289
DEGREE = 1024
FIDELITY = 7

public_key1, private_key1 = generate_keys(MODULUS, DEGREE, FIDELITY)
auxiliary_errors1 = generate_auxiliary_error_polynomials(DEGREE, FIDELITY)

enc = rlws_encrypt(b'Hello', public_key1, auxiliary_errors1, MODULUS, DEGREE)
dec = rlws_decrypt(enc, private_key1, MODULUS, DEGREE)

print(enc)
print(dec)
