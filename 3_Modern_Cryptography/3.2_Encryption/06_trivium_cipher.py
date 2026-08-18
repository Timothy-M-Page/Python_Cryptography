import secrets


k = secrets.randbits(80)
i_v = secrets.randbits(80)


def trivium_key_stream(plaintext: str, key: int, iv: int) -> bytes:
    key_bits = [(key >> i) & 1 for i in range(80)]
    iv_bits = [(iv >> i) & 1 for i in range(80)]

    a = [0] * 93
    a[0:80] = key_bits

    b = [0] * 84
    b[0:80] = iv_bits

    c = [0] * 111
    c[109:111] = [1, 1, 1]

    for i in range(1152):
        A = (c[65] + c[110] + c[109]*c[108] + a[68]) % 2
        B = (a[65] + a[92] + a[91]*a[90] + b[77]) % 2
        C = (b[68] + b[83] + b[82]*b[81] + c[86]) % 2

        a = [A] + a[:-1]
        b = [B] + b[:-1]
        c = [C] + c[:-1]

    num_bits = len(plaintext.encode("utf-8")) * 8

    bits = ""

    for i in range(num_bits):
        new_bit = (a[65] + a[92] + b[83] + b[68] + c[65] + c[110]) % 2
        bits += str(new_bit)

        A = (c[65] + c[110] + c[109]*c[108] + a[68]) % 2
        B = (a[65] + a[92] + a[91]*a[90] + b[77]) % 2
        C = (b[68] + b[83] + b[82]*b[81] + c[86]) % 2

        a = [A] + a[:-1]
        b = [B] + b[:-1]
        c = [C] + c[:-1]

    key_stream = int(bits, 2).to_bytes(len(bits) // 8, byteorder="big")

    return key_stream


def trivium_encrypt(plaintext: str, key_stream: bytes) -> bytes:
    pt = plaintext.encode("utf-8")
    ciphertext = bytes(p ^ x for p, x in zip(pt, key_stream))
    return ciphertext


def trivium_encrypt_decrypt(ciphertext: bytes, key_stream: bytes) -> str:
    plaintext = bytes(p ^ x for p, x in zip(ciphertext, key_stream))
    return plaintext.decode("utf-8", errors="replace")
