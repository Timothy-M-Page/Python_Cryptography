import matplotlib.pyplot as plt


def hamming_weight(n: int) -> int:
    return bin(n).count('1')


def bit_count_height(n: int) -> int:
    steps = 0
    while n > 1:
        n = hamming_weight(n)
        steps += 1
    return steps


"""
We have with

r(n) = bit_count_height(n)
h(n) = hamming_weight(n)

r(n) = 1 + r(h(n))

If a(n) is the first natural N to have r(N) = n e.g
a(1) = 2
a(2) = 3
a(3) = 7
a(4) = 127

then a(n) = (2**a(n-1)) - 1

Since we ask a(n) = k, let the solution be N
then r( h(N) ) = k - 1
Since a(n) is the least with r(n) = k, we choose the least which has a(n) = k-1
Thus h(N) = a(n-1)
so we need the first number with a(n-1) 1's in it's binary, that is a(n-1)*1
or mathematically 2^(a(n-1)) - 1

So a(5) = 2**127 - 1
a(6) = 2**(2**127-1) - 1 etc


First 2**(n-1) elements after 2**n are repeated elements of 2**(n-1) to 2**n
"""



