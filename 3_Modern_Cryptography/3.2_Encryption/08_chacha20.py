import secrets

n = secrets.randbits(64)
k = secrets.randbits(256)


def left_rotate_32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def qr(a: int, b: int, c: int, d: int) -> list[int]:
    a1 = (a + b) & 0xFFFFFFFF
    d1 = left_rotate_32((d ^ a1) & 0xFFFFFFFF, 16)
    c1 = (c + d1) & 0xFFFFFFFF
    b1 = left_rotate_32((b ^ c1) & 0xFFFFFFFF, 12)
    a2 = (a1 + b1) & 0xFFFFFFFF
    d2 = left_rotate_32((d1 ^ a2) & 0xFFFFFFFF, 8)
    c2 = (c1 + d2) & 0xFFFFFFFF
    b2 = left_rotate_32((b1 ^ c2) & 0xFFFFFFFF, 7)
    return [a2, b2, c2, d2]


def cha_cha_20_key_stream(plaintext: str, key: int, nonce: int) -> bytes:
    pt = plaintext.encode("utf-8")
    num_blocks = (len(pt) + 63) // 64

    nonce_bytes = nonce.to_bytes(8, "little")

    k_bytes = key.to_bytes(32, "little")
    k_words = [int.from_bytes(k_bytes[i:i + 4], "little")
               for i in range(0, 32, 4)]
    k0, k1, k2, k3, k4, k5, k6, k7 = k_words

    c_bytes = "expand 32-byte k".encode("ascii")
    c_words = [int.from_bytes(c_bytes[i:i + 4], "little")
               for i in range(0, 16, 4)]
    c0, c1, c2, c3 = c_words

    n0 = int.from_bytes(nonce_bytes[0:4], "little")
    n1 = int.from_bytes(nonce_bytes[4:8], "little")

    p0 = 0
    p1 = 0

    key_stream = b""

    for _ in range(num_blocks):
        U = [c0, c1, c2, c3, k0, k1, k2, k3, k4, k5, k6, k7, p0, p1, n0, n1]
        initial_state = U.copy()

        for iteration in range(10):
            w = qr(U[0], U[4], U[8], U[12])
            x = qr(U[1], U[5], U[9], U[13])
            y = qr(U[2], U[6], U[10], U[14])
            z = qr(U[3], U[7], U[11], U[15])

            U = [w[0], x[0], y[0], z[0],
                 w[1], x[1], y[1], z[1],
                 w[2], x[2], y[2], z[2],
                 w[3], x[3], y[3], z[3]]

            w = qr(U[0], U[5], U[10], U[15])
            x = qr(U[1], U[6], U[11], U[12])
            y = qr(U[2], U[7], U[8], U[13])
            z = qr(U[3], U[4], U[9], U[14])

            U = [w[0], x[0], y[0], z[0],
                 z[1], w[1], x[1], y[1],
                 y[2], z[2], w[2], x[2],
                 x[3], y[3], z[3], w[3]]

        for x in range(len(U)):
            U[x] = (U[x] + initial_state[x]) % 2 ** 32

        p0 = (p0 + 1) & 0xFFFFFFFF
        if p0 == 0:
            p1 = (p1 + 1) & 0xFFFFFFFF

        key_stream += b"".join(
            word.to_bytes(4, "little") for word in U)

    return key_stream


def cha_cha_20_encrypt(plaintext: str, key_stream: bytes) -> bytes:
    pt = plaintext.encode("utf-8")
    ciphertext = bytes(p ^ x for p, x in zip(pt, key_stream))
    return ciphertext


def cha_cha_20_decrypt(ciphertext: bytes, key_stream: bytes) -> str:
    plaintext = bytes(p ^ x for p, x in zip(ciphertext, key_stream))
    return plaintext.decode("utf-8", errors="replace")
