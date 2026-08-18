import math
import hashlib
import secrets
from Crypto.Util.number import getPrime, isPrime


def generate_safe_prime(bits: int):
    """
    If p = 2q + 1 then the size of the resultant group will be p-1 = 2q.
    Hence, the order of the elements can only be one of 1, 2, q or 2q
    Allowing us to easily check when we have a generator when order = 2q.
    """
    while True:
        q = getPrime(bits - 1)
        p = 2*q + 1

        if isPrime(p):
            return p, q


def find_generator(p: int, q: int):
    """
    Choose an element != 1 in the group, if the order is not 2 or q then the
    order must be 2q, that is the order of the whole group, hence a generator.
    """
    while True:
        g = secrets.randbelow(p - 3) + 2

        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def message_to_int(message: str, prime: int) -> int:
    # Hash the message
    digest = hashlib.sha256(message.encode()).digest()
    # Convert to integer
    m_int = int.from_bytes(digest, byteorder='big')
    # Reduce modulo p-1 to fit in group
    return m_int % (prime - 1)


def generate_elgamal_signature(message: str, public_key: tuple, private_key: int) -> tuple[int, int]:
    prime = public_key[0]
    generator = public_key[1]

    hashed_message = message_to_int(message, prime)

    ephemeral_key = secrets.randbelow(prime - 2) + 1
    while math.gcd(ephemeral_key, prime-1) != 1:
        ephemeral_key = secrets.randbelow(prime - 2) + 1

    key_inverse = pow(ephemeral_key, -1, prime - 1)
    r = pow(generator, ephemeral_key, prime)
    s = ((hashed_message - private_key*r) * key_inverse) % (prime - 1)
    return r, s


def verify_elgamal_signature(message: str, public_key: tuple, signature: tuple) -> bool:
    prime = public_key[0]
    generator = public_key[1]
    public_power = public_key[2]
    r = signature[0]
    s = signature[1]
    hashed_message = message_to_int(message, prime)

    t = (pow(public_power, r, prime) * pow(r, s, prime)) % prime
    T = pow(generator, hashed_message, prime)

    return t == T


prime1, prime2 = generate_safe_prime(64)
generator = find_generator(prime1, prime2)

private_exponent = secrets.randbelow(prime1 - 2) + 1
public_power = pow(generator, private_exponent, prime1)

public_key = (prime1, generator, public_power)
private_key = private_exponent

sig = generate_elgamal_signature("hello!", public_key, private_key)

print(verify_elgamal_signature("hello!", public_key, sig))
