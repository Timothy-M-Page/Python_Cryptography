import math


K_VALUES = [math.floor(2**32 * abs(math.sin(i + 1))) for i in range(0, 64)]

ROTATION_VALUES = ([7, 12, 17, 22]*4 + [5, 9, 14, 20]*4
                   + [4, 11, 16, 23]*4 + [6, 10, 15, 21]*4)


def left_rotate(value: int, shift: int):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def message_format(message: str):
    msg = message.encode("utf-8")
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg += b"\x80"
    while (len(msg) % 64) != 56:
        msg += b"\x00"
    msg += bit_len.to_bytes(8, "little")
    return [msg[i:i+64] for i in range(0, len(msg), 64)]


def md5(message: str) -> str:
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    blocks = message_format(message)

    for block in blocks:
        a = a0
        b = b0
        c = c0
        d = d0

        words = [int.from_bytes(block[i:i+4], "little")
                 for i in range(0, 64, 4)]

        for i in range(0, 64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7*i) % 16

            f = (f + a + K_VALUES[i] + words[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + left_rotate(f, ROTATION_VALUES[i])) % 2**32

        a0 = (a0 + a) % 2**32
        b0 = (b0 + b) % 2**32
        c0 = (c0 + c) % 2**32
        d0 = (d0 + d) % 2**32

    digest = (
            a0.to_bytes(4, "little") +
            b0.to_bytes(4, "little") +
            c0.to_bytes(4, "little") +
            d0.to_bytes(4, "little"))

    return digest.hex()
