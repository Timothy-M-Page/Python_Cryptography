from typing import Any
import numpy as np


def encode_message(message: bytes, modulus: int) -> list[int]:
    """
    Many encoding schemes exist, we choose a simple one here
    Mapping 0 to 0 and 1 to modulus//2
    """
    bit_string = ''.join(f'{byte:08b}' for byte in message)
    half_modulus = modulus // 2
    encoded_bits = []

    for bit in bit_string:
        if bit == "0":
            encoded_bits.append(0)
        else:
            encoded_bits.append(half_modulus)

    return encoded_bits


def decode_message(cipher_message: list[int], modulus: int) -> bytes:
    bit_string = ""
    threshold = modulus // 4

    for encoded_bit in cipher_message:
        if abs(encoded_bit) < threshold:
            bit_string += "0"
        else:
            bit_string += "1"

    return bytes(int(bit_string[i:i + 8], 2) for i in range(0, len(bit_string), 8))


def encrypt_encoded_bit(encoded_bit: int, public_key: tuple,
                        random_vector: np.array, auxiliary_error: np.array,
                        random_value: int, modulus: int) -> tuple[np.array, int]:

    A, target = public_key
    u = (A.T @ random_vector + auxiliary_error) % modulus
    v = (target.T @ random_vector + random_value + encoded_bit) % modulus

    return u, int(v.item())


def decrypt_encoded_bit(encrypted_bit: tuple, private_key: np.array, modulus: int) -> int:
    return (encrypted_bit[1] - (private_key.T @ encrypted_bit[0])) % modulus


def lws_encrypt(plaintext: bytes, public_key: tuple,
                random_vector: np.array, auxiliary_error: np.array,
                random_value: int, modulus: int) -> list[tuple[Any, int]]:

    # Note the random value, random vector and private key
    # must all be small compared to the modulus for the decryption threshold.

    encoded_message = encode_message(plaintext, modulus)
    encrypted_bits = []
    for bit in encoded_message:
        encrypted_bit = encrypt_encoded_bit(bit, public_key, random_vector, auxiliary_error, random_value, modulus)
        encrypted_bits.append(encrypted_bit)

    return encrypted_bits


def lws_decrypt(ciphertext: list, private_key: np.array, modulus: int) -> bytes:
    decrypted_bits = []
    for encrypted_bit in ciphertext:
        decrypted_bit = decrypt_encoded_bit(encrypted_bit, private_key, modulus)
        decrypted_bits.append(decrypted_bit)
    return decode_message(decrypted_bits, modulus)
