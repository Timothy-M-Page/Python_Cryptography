import hashlib


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


def rsa_sign(message: bytes, prime1: int, prime2: int, private_exponent: int) -> int:
    """
    Create RSA signature by signing SHA256 hash of message.
    """

    digest = hashlib.sha256(message).digest()
    digest_int = int.from_bytes(digest, "big")

    signature = fast_decrypt(digest_int, private_exponent, prime1, prime2)

    return signature


def rsa_verify(message: bytes, signature: int, public_exponent: int, modulus: int) -> bool:
    """
    Verify RSA signature.
    """

    digest = hashlib.sha256(message).digest()
    digest_int = int.from_bytes(digest, "big")

    recovered = pow(signature, public_exponent, modulus)

    return recovered == digest_int