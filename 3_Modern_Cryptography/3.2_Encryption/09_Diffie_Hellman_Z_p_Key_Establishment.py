import hashlib
import secrets

from sympy import randprime

# Security  Prime Size
# 112-bit	2048 bits
# 128-bit	3072 bits
# 192-bit	7680 bits
# 256-bit	15360 bits

base1 = 2
prime1 = randprime(2**(2048-1), 2**2048)

alice_exponent = secrets.randbits(256)
bob_exponent = secrets.randbits(256)


def generate_public_key(base: int, exponent: int, prime: int) -> int:
    return pow(base, exponent, prime)


def derive_shared_key(public_key:int, exponent: int, prime: int) -> int:
    return pow(public_key, exponent, prime)


alice_public = generate_public_key(base1, alice_exponent, prime1)
bob_public = generate_public_key(base1, bob_exponent, prime1)

alice_key = derive_shared_key(bob_public, alice_exponent, prime1)
bob_key = derive_shared_key(alice_public, bob_exponent, prime1)

assert alice_key == bob_key

key = hashlib.sha256(alice_key.to_bytes((alice_key.bit_length() + 7) // 8, "big")).hexdigest()

print(key)
