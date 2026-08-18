import math
import os
import secrets
import hashlib

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
        x = (m ** 2 - point2[0] - point1[0]) % p
        y = -(m * x + c) % p
        return x, y

    if point1 == point2 and point1[1] != 0:
        m = ((3 * (point1[0] ** 2) + a) * modular_inverse(2 * point1[1],
                                                          p)) % p
        c = (point1[1] - m * point1[0]) % p
        x = (m ** 2 - point2[0] - point1[0]) % p
        y = -(m * x + c) % p
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

alice_private_key = int.from_bytes(os.urandom(32), 'big') % point_order + 1
alice_public_key = point_exponent(CURVE_PARAMETERS, base_point,
                                  alice_private_key)

bob_private_key = secrets.randbelow(point_order) + 1
bob_public_key = point_exponent(CURVE_PARAMETERS, base_point, bob_private_key)

alice_shared_secret = point_exponent(CURVE_PARAMETERS, bob_public_key,
                                     alice_private_key)
bob_shared_secret = point_exponent(CURVE_PARAMETERS, alice_public_key,
                                   bob_private_key)


def message_to_int(message: str, modulus: int) -> int:
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, byteorder='big') % modulus


def generate_elliptic_curve_signature(message: str, base_point: tuple,
    private_key: int, prime: int, parameters: tuple[int, int, int], order: int) -> tuple[int, int]:

    hashed_message = message_to_int(message, order)
    ephemeral_key = secrets.randbelow(order - 1) + 1
    key_inverse = pow(ephemeral_key, -1, order)

    R = point_exponent(parameters, base_point, ephemeral_key)
    r = R[0] % order
    s = ((hashed_message + private_key * r) * key_inverse) % order
    return r, s


def verify_elliptic_curve_signature(message: str, signature: tuple[int, int],
    public_key: tuple, base_point: tuple, order: int, parameters: tuple[int, int, int]) -> bool:

    r, s = signature
    if not (1 <= r < order and 1 <= s < order):
        return False

    hashed_message = message_to_int(message, order)

    w = pow(s, -1, order)
    u1 = (hashed_message * w) % order
    u2 = (r * w) % order

    point1 = point_exponent(parameters, base_point, u1)
    point2 = point_exponent(parameters, public_key, u2)
    verification_point = add_points(parameters, point1, point2)

    return verification_point[0] % order == r
