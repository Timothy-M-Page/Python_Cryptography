from typing import Callable
import secrets
"""
The confusion and diffusion of any hash function may be measured by :


1. Looking at the distribution of letters in the output alphabet to gauge
randomness across a range of inputs.

2. Taking a block length input, flipping each bit and measuring how many bits
flip in the output on average to determine average diffusion


"""


def count_bit_disagreements(byte_string1: bytes, byte_string2: bytes) -> int:
    int1 = int.from_bytes(byte_string1, byteorder='big')
    int2 = int.from_bytes(byte_string2, byteorder='big')
    count = bin(int1 ^ int2).count('1')
    return count


def confusion_measure(hash_function: Callable[[bytes], bytes],
                      block_size: int, number_of_rounds: int = 10) -> float:

    outer_round_averages = []

    for index in range(number_of_rounds):
        block = secrets.token_bytes(block_size)
        original_hash = hash_function(block)
        inner_round_averages = []

        for n in range(block_size):
            bit_flip = int.from_bytes(block, byteorder='big') ^ (1 << n)
            hash = hash_function(bit_flip.to_bytes(block_size, byteorder='big'))
            number_of_flips = count_bit_disagreements(original_hash, hash)
            inner_round_averages.append(number_of_flips/block_size)

        outer_round_averages.append(sum(inner_round_averages)/block_size)

    return sum(outer_round_averages)/number_of_rounds


def test_hash_function(string: bytes) -> bytes:
    hash = int.from_bytes(string, byteorder='big')
    for x in range(100000, 200000, 1000):
        hash = hash ^ x
    return hash.to_bytes((hash.bit_length() + 7) // 8, byteorder='big')
