import secrets


def left_rotate_32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def qr(a: int, b: int, c: int, d: int) -> list[int]:
    B = b ^ left_rotate_32((a + d) & 0xFFFFFFFF, 7)
    C = c ^ left_rotate_32((B + a) & 0xFFFFFFFF, 9)
    D = d ^ left_rotate_32((B + C) & 0xFFFFFFFF, 13)
    A = a ^ left_rotate_32((D + C) & 0xFFFFFFFF, 18)
    return [A, B, C, D]


n = secrets.randbits(64)
k = secrets.randbits(256)


def salsa20_key_stream(plaintext: str, key: int, nonce: int) -> bytes:
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
        U = [c0, k0, k1, k2, k3, c1, n0, n1, p0, p1, c2, k4, k5, k6, k7, c3]
        initial_state = U

        for iteration in range(10):
            w = qr(U[0], U[4], U[8], U[12])
            x = qr(U[5], U[9], U[13], U[1])
            y = qr(U[10], U[14], U[2], U[6])
            z = qr(U[15], U[3], U[7], U[11])

            U = [w[0], x[3], y[2], z[1],
                 w[1], x[0], y[3], z[2],
                 w[2], x[1], y[0], z[3],
                 w[3], x[2], y[1], z[0]]

            w = qr(U[0], U[1], U[2], U[3])
            x = qr(U[5], U[6], U[7], U[4])
            y = qr(U[10], U[11], U[8], U[9])
            z = qr(U[15], U[12], U[13], U[14])

            U = [w[0], w[1], w[2], w[3],
                 x[3], x[0], x[1], x[2],
                 y[2], y[3], y[0], y[1],
                 z[1], z[2], z[3], z[0]]

        for x in range(len(U)):
            U[x] = (U[x] + initial_state[x]) % 2 ** 32

        p0 = (p0 + 1) & 0xFFFFFFFF
        if p0 == 0:
            p1 = (p1 + 1) & 0xFFFFFFFF

        key_stream += b"".join(
            word.to_bytes(4, "little") for word in U)

    return key_stream


def salsa20_encrypt(plaintext: str, key_stream: bytes) -> bytes:
    pt = plaintext.encode("utf-8")
    ciphertext = bytes(p ^ x for p, x in zip(pt, key_stream))
    return ciphertext


def salsa20_decrypt(ciphertext: bytes, key_stream: bytes) -> str:
    plaintext = bytes(p ^ x for p, x in zip(ciphertext, key_stream))
    return plaintext.decode("utf-8", errors="replace")
