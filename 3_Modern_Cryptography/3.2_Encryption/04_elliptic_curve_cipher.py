import math
import os
import secrets

identity = ("O", "O")


def modular_inverse(g: int, mod: int) -> int:
    if math.gcd(g, mod) != 1:
        raise ValueError(f'{g} has no inverse mod {mod}.')
    return pow(g, -1, mod)


def add_points(curve_params: tuple[int, int, int],
               point1: tuple, point2: tuple) -> tuple:
    # All possible cases of two points being added.
    a, b, p = curve_params

    if point1 == identity:
        return point2
    if point2 == identity:
        return point1

    if point1 != point2 and point1[0] == point2[0]:
        return identity

    if point1 != point2 and point1[0] != point2[0]:
        m = ((point2[1] - point1[1]) *
             modular_inverse((point2[0] - point1[0]), p)) % p
        c = (point1[1] - m * point1[0]) % p
        x = (m**2 - point2[0] - point1[0]) % p
        y = -(m*x + c) % p
        return x, y

    if point1 == point2 and point1[1] != 0:
        m = ((3*(point1[0]**2) + a) * modular_inverse(2*point1[1], p)) % p
        c = (point1[1] - m * point1[0]) % p
        x = (m**2 - point2[0] - point1[0]) % p
        y = -(m*x + c) % p
        return x, y

    if point1 == point2 and point1[1] == 0:
        return identity


def point_exponent(curve_params: tuple[int, int, int],
                   point1: tuple, exponent: int) -> tuple:
    # Double-and-add method for quick exponentiation.
    if exponent == 0:
        return identity
    result = identity
    power = point1
    while exponent > 0:
        if exponent % 2 == 1:  # If the current bit is 1, add current power.
            result = add_points(curve_params, result, power)
        power = add_points(curve_params, power, power)
        exponent //= 2  # Move to the next bit.
    return result


"""
Choice of elliptic curve :

NIST recommends in their publication 'Recommendations for Discrete 
Logarithm-based Cryptography' (2023):

'The principal parameters for elliptic curve cryptography are the elliptic 
curve E and a designated point G on E called the base point. The base point 
has order n, which is a large prime. The number of points on the curve is h⋅n 
for some integer h (the cofactor), which is not divisible by n.
For efficiency reasons, it is desirable for the cofactor to be small.

If an elliptic curve has a base point of order n, then the security strength
will be approximately one half of the bit length of n. (The security strength
is determined by the difficulty of solving the EC-DLP done with Pollard's alg.)

Security Strength   Recommended Curves
112                 P-224, K-233, B-233
128                 P-256, W-25519, Curve25519, Edwards25519, K-283, B-283
192                 P-384, K-409, B-409
224                 W-448, Curve448, Edwards448, E448
256                 P-521, K-571, B-571'

We choose P-256 (secp256r1), with parameters:
"""


def p_224() -> tuple:
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    base_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    base_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    return a, b, p, base_x, base_y, order


CURVE_PARAMETERS = (p_224()[0], p_224()[1], p_224()[2])
base_point = (p_224()[3], p_224()[4])
point_order = p_224()[5]

"""
Key Generation :

os.urandom() provides cryptographically secure random numbers sourced from 
the operating system.

The secrets package in Python provides cryptographically secure random numbers,
suitable for generating keys, tokens, and other sensitive data.
"""


alice_private_key = int.from_bytes(os.urandom(32), 'big') % point_order + 1

bob_private_key = secrets.randbelow(point_order) + 1

alice_public_key = point_exponent(CURVE_PARAMETERS,
                                  base_point, alice_private_key)

bob_public_key = point_exponent(CURVE_PARAMETERS,
                                base_point, bob_private_key)


"""
We may use the elliptic curve Diffie-Hellman protocol to allow two parties
to secure a secret key.
"""

alice_shared_secret = point_exponent(CURVE_PARAMETERS,
                                     bob_public_key, alice_private_key)

bob_shared_secret = point_exponent(CURVE_PARAMETERS,
                                   alice_public_key, bob_private_key)

assert alice_shared_secret == bob_shared_secret



"""
Here are some other curves :
"""


def p_224() -> tuple:
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    base_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    base_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    return a, b, p, base_x, base_y, order


def p_384() -> tuple:
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
    a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
    b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef

    base_x =0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
    base_y =0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
    order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973

    return a, b, p, base_x, base_y, order


def w_448() -> tuple:
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    a = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffffffffffffffffffffffffffffffffffffffffffffe1a76d41f
    b = 0x5ed097b425ed097b425ed097b425ed097b425ed097b425ed097b425e71c71c71c71c71c71c71c71c71c71c71c71c71c71c72c87b7cc69f70

    base_x = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000cb91
    base_y = 0x7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1a
    order = 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779

    return a, b, p, base_x, base_y, order


def p_521() -> tuple:
    p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    a = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
    b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00

    base_x = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
    base_y = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
    order = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

    return a, b, p, base_x, base_y, order