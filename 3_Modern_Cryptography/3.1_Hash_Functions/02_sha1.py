
def left_rotate_32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def message_format(message: str):
    msg = message.encode("utf-8")
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg += b"\x80"
    while (len(msg) % 64) != 56:
        msg += b"\x00"
    msg += bit_len.to_bytes(8, "big")
    return [msg[i:i+64] for i in range(0, len(msg), 64)]


def sha1(message: str) -> str:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    blocks = message_format(message)

    for block in blocks:
        words = [int.from_bytes(block[i:i+4], "big")
                 for i in range(0, len(block), 4)]

        for i in range(16, 80):
            words.append(left_rotate_32(words[i-3] ^ words[i-8] ^
                                        words[i-14] ^ words[i-16], 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = 0
        k = 0

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            if 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            if 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            if 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = ((left_rotate_32(a, 5))
                    + f + e + k + words[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate_32(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    x = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return f"{x:040x}"
