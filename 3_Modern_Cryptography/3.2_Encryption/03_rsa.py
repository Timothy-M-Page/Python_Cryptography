import hashlib
import secrets
from math import gcd

from Crypto.Util.number import getPrime


def fast_decrypt(base: int, power: int, prime1: int, prime2: int) -> int:
    """
    Decryption may be performed quickly using the fact that the recipient of
    messages knows p and q, thus can calculate the exponent by using the
    chinese remainder theorem to combine the exponents for each prime.

    Increases the speed of exponentiation by a factor of 4.
    """
    n = prime1 * prime2

    base1 = base % prime1
    base2 = base % prime2

    exponent1 = power % (prime1 - 1)
    exponent2 = power % (prime2 - 1)

    power1 = pow(base1, exponent1, prime1)
    power2 = pow(base2, exponent2, prime2)

    inverse1 = pow(prime1, -1, prime2)
    inverse2 = pow(prime2, -1, prime1)

    return ((prime2 * inverse2 * power1) + (prime1 * inverse1 * power2)) % n


def mgf1(seed: bytes, length: int) -> bytes:
    result = b""
    counter = 0
    while len(result) < length:
        counter_bytes = counter.to_bytes(4, "big")
        result += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1
    return result[:length]


def oaep_encode(message: bytes, modulus_size: int) -> bytes:
    """
    Optimum Asymmetric encryption Padding (OAEP) adds randomness to the message
    preventing malleability of the cipher
    """
    empty_hash = hashlib.sha256(b"").digest()
    hash_size = hashlib.sha256().digest_size

    zero_padding = b'\x00' * (modulus_size - len(message) - (2 * hash_size) - 1)
    data_block = empty_hash + zero_padding + b'\x01' + message

    seed = secrets.token_bytes(hash_size)

    masked_data_block = bytes(a ^ b for a, b in zip(data_block, mgf1(seed, len(data_block))))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_data_block, hash_size)))

    return b'\x00' + masked_seed + masked_data_block


def oaep_decode(encoded: bytes) -> bytes:
    """
    Remove OAEP padding and recover the original message.
    """
    hash_size = hashlib.sha256().digest_size
    empty_hash = hashlib.sha256(b"").digest()

    if encoded[0] != 0x00:
        raise ValueError("Invalid OAEP encoding: missing leading 0x00")

    masked_seed = encoded[1:1+hash_size]
    masked_data_block = encoded[1+hash_size:]

    seed = bytes(a ^ b for a, b in zip(masked_seed, mgf1(masked_data_block, hash_size)))
    data_block = bytes(a ^ b for a, b in zip(masked_data_block, mgf1(seed, len(masked_data_block))))

    lHash_prime = data_block[:hash_size]
    if lHash_prime != empty_hash:
        raise ValueError("Invalid OAEP encoding: label hash mismatch")

    try:
        separator_index = data_block.index(b'\x01', hash_size)
    except ValueError:
        raise ValueError("Invalid OAEP encoding: missing 0x01 separator")

    return data_block[separator_index + 1:]


def generate_key_pair(bit_length: int):

    public_exponent = 2**16 + 1

    """
    This value for the exponent is chosen due to its low Hamming
    weight allowing efficient exponentiation via the square and multiply
    algorithm. 1 is added such that the exponent will share no factors with
    phi(n) which is even for all n > 2.
    """

    while True:
        prime1 = getPrime(bit_length)
        prime2 = getPrime(bit_length)
        phi = (prime1 - 1) * (prime2 - 1)
        if gcd(public_exponent, phi) == 1:
            break

    private_exponent = pow(public_exponent, -1, phi)

    n = prime1 * prime2

    public_key = (public_exponent, n)
    private_key = (prime1, prime2, private_exponent)

    return [public_key, private_key]


def rsa_encrypt(message: bytes, public_exponent: int, modulus: int) -> int:

    modulus_bytes = (modulus.bit_length() + 7) // 8

    if len(message) > modulus_bytes - 2 * hashlib.sha256().digest_size - 2:
        raise ValueError("Message too long for OAEP with this modulus")

    padded_message = oaep_encode(message, modulus_bytes)
    message_int = int.from_bytes(padded_message, byteorder="big")

    return pow(message_int, public_exponent, modulus)


def rsa_decrypt(ciphertext: int, prime1: int, prime2: int, private_exponent: int, modulus: int) -> bytes:
    padded_message_int = fast_decrypt(ciphertext, private_exponent, prime1, prime2)

    modulus_bytes = (modulus.bit_length() + 7) // 8
    padded_bytes = padded_message_int.to_bytes(modulus_bytes, byteorder="big")

    message = oaep_decode(padded_bytes)
    return message
