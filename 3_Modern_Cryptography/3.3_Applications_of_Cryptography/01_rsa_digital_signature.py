import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa


# Generate a private and public key.
private_key_example = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_example = private_key_example.public_key()

e = public_key_example.public_numbers().e
n = public_key_example.public_numbers().n
d = private_key_example.private_numbers().d


def mgf1(seed: bytes, length: int) -> bytes:
    result = b""
    counter = 0
    while len(result) < length:
        counter_bytes = counter.to_bytes(4, "big")
        result += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1
    return result[:length]


def pss_encode(message: bytes, modulus_size: int, salt_length: int = 32) -> bytes:
    """
    EMSA-PSS encoding used for RSA signatures.
    Produces an encoded message of length equal to the modulus.
    """

    hash_func = hashlib.sha256
    hash_size = hash_func().digest_size

    if modulus_size < hash_size + salt_length + 2:
        raise ValueError("Encoding error")

    message_hash = hash_func(message).digest()

    salt = secrets.token_bytes(salt_length)

    M_prime = b'\x00' * 8 + message_hash + salt
    H = hash_func(M_prime).digest()

    padding_length = modulus_size - salt_length - hash_size - 2
    PS = b'\x00' * padding_length

    DB = PS + b'\x01' + salt

    db_mask = mgf1(H, modulus_size - hash_size - 1)
    masked_DB = bytes(a ^ b for a, b in zip(DB, db_mask))

    EM = masked_DB + H + b'\xbc'

    return EM


def pss_verify(message: bytes, encoded: bytes, modulus_size: int, salt_length: int = 32) -> bool:
    hash_func = hashlib.sha256
    hash_size = hash_func().digest_size

    if encoded[-1] != 0xbc:
        return False

    masked_DB = encoded[:modulus_size - hash_size - 1]
    H = encoded[modulus_size - hash_size - 1:-1]

    db_mask = mgf1(H, modulus_size - hash_size - 1)
    DB = bytes(a ^ b for a, b in zip(masked_DB, db_mask))

    padding_length = modulus_size - hash_size - salt_length - 2

    if DB[:padding_length] != b'\x00' * padding_length:
        return False

    if DB[padding_length] != 0x01:
        return False

    salt = DB[-salt_length:]

    message_hash = hash_func(message).digest()
    M_prime = b'\x00' * 8 + message_hash + salt
    H_check = hash_func(M_prime).digest()

    return H == H_check


def rsa_pss_sign(message: bytes, private_exponent: int, modulus: int) -> int:
    modulus_bytes = (modulus.bit_length() + 7) // 8
    encoded = pss_encode(message, modulus_bytes)
    encoded_int = int.from_bytes(encoded, "big")
    signature = pow(encoded_int, private_exponent, modulus)
    return signature


def rsa_pss_verify(message: bytes, signature: int, public_exponent: int, modulus: int) -> bool:
    modulus_bytes = (modulus.bit_length() + 7) // 8
    encoded_int = pow(signature, public_exponent, modulus)
    encoded = encoded_int.to_bytes(modulus_bytes, "big")
    return pss_verify(message, encoded, modulus_bytes)
