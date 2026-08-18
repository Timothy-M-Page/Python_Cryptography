# K_Values are the first 8 hex characters of the decimal parts of the
# first 64 cube roots of prime numbers.

K_VALUES = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def pad_and_block(message: bytes) -> list[list[int]]:
    """
    Padding consists of adding a 1 to the bit string, padding with zeros
    and adding a 64 bit representation of the length of the initial message
    such that the padded message length is a multiple of 64 bytes.
    """
    padded = message + b'\x80'
    padded += b'\x00' * ((56 - len(padded) % 64) % 64)
    padded += (8 * len(message)).to_bytes(8, byteorder="big")

    blocks = [[int.from_bytes(padded[i + j:i + j + 4], "big")
               for j in range(0, 64, 4)] for i in range(0, len(padded), 64)]

    return blocks


def right_rotate_32(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def sigma0(word: int) -> int:
    return (right_rotate_32(word, 7) ^ right_rotate_32(word, 18)
            ^ (word >> 3))


def sigma1(word: int) -> int:
    return (right_rotate_32(word, 17) ^ right_rotate_32(word, 19)
            ^ (word >> 10))


def extend_words(words: list[int]) -> list[int]:
    for index in range(16, 64):
        new_word = (sigma1(words[index - 2]) + words[index - 7]
                    + sigma0(words[index - 15]) + words[index - 16])
        words.append(new_word & 0xFFFFFFFF)
    return words


def choice(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z)) & 0xFFFFFFFF


def majority(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF


def sum0(x: int) -> int:
    return (right_rotate_32(x, 2) ^ right_rotate_32(x, 13)
            ^ right_rotate_32(x, 22)) & 0xFFFFFFFF


def sum1(x: int) -> int:
    return (right_rotate_32(x, 6) ^ right_rotate_32(x, 11)
            ^ right_rotate_32(x, 25)) & 0xFFFFFFFF


def sha2(message: bytes) -> bytes:
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    blocks = pad_and_block(message)

    for block in blocks:
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        message_schedule = extend_words(block)

        for i in range(64):
            temp1 = (h + sum1(e) + choice(e, f, g) + K_VALUES[i]
                     + message_schedule[i]) & 0xFFFFFFFF
            temp2 = (sum0(a) + majority(a, b, c)) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return b''.join(h.to_bytes(4, 'big') for h in [h0, h1, h2, h3, h4, h5, h6, h7])