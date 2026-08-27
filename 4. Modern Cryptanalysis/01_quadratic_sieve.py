import math
from itertools import combinations

"""
If N = pq is the modulus in RSA then we may find factors of N by solving
x**2 - y**2 == 0 mod(N).
In such a case it follows N divides x**2 - y**2 = (x-y)(x+y).

Provided x != ±y mod(N) the factors of N must split between the two terms.

We find solutions to x**2 == N mod(p) for every prime p in a factor base,
using these solutions, x, we find the primes dividing x**2 - N, then factor the 
resulting values over the factor base then combine the resulting factorisations 
to reconstruct a square by looking at the power vectors mod 2.
"""


def prime_factors(n: int) -> list[tuple[int, int]]:
    factors = []
    n = abs(n)
    p = 2
    while p * p <= n:
        count = 0
        while n % p == 0:
            count += 1
            n //= p
        if count > 0:
            factors.append((p, count))
        p += 1
    if n > 1:
        factors.append((n, 1))
    return factors


def is_quadratic_residue(a: int, p: int) -> bool:
    return pow(a, (p - 1) // 2, p) in (0, 1)


def quad_residue_primes_up_to(x: int, n: int) -> list[int]:
    """
     The only primes we need to consider are those up to the smoothness bound,
     since we are checking for p dividing x**2 - n, the prime in question must
     be a quadratic residue, hence we may also filter out those that are not.
     """
    primes = []
    for n in range(2, x + 1):
        if all(n % p != 0 for p in primes if p * p <= n):
            primes.append(n)

    return [p for p in primes if p == 2 or is_quadratic_residue(n, p)]


def p_adic_valuation(p: int, n: int) -> int:
    count = 0
    n = abs(n)
    while n % p == 0:
        count += 1
        n //= p
    return count


def find_square(vectors: list[list[int]]) -> list[int] | None:
    for size in range(1, len(vectors) + 1):
        for combination in combinations(range(len(vectors)), size):

            result = [0] * len(vectors[0])

            for i in combination:
                result = [a ^ b for a, b in zip(result, vectors[i])]

            if all(bit == 0 for bit in result):
                return list(combination)

    return None


def quadratic_sieve(n: int, smooth_bound: int, search_range: int) -> tuple[int, int] | str:
    factor_base = quad_residue_primes_up_to(smooth_bound, n)
    prime_moduli_solutions = {}

    for prime in factor_base:
        roots = []
        for x in range(prime):
            if (x**2 - n) % prime == 0:
                roots.append(x)

        prime_moduli_solutions[prime] = roots

    start = math.ceil(math.sqrt(n))
    factor_dictionary = {}

    for integer in range(start - search_range, start + search_range):
        value = integer ** 2 - n
        remaining = abs(value)
        entry = []

        for prime in factor_base:
            if remaining % prime == 0:
                power = p_adic_valuation(prime, remaining)
                entry.append((prime, power))
                remaining //= prime ** power

        if remaining == 1:
            factor_dictionary[integer] = entry

    vectors = []
    integers = []
    prime_indices = {prime: i for i, prime in enumerate(factor_base)}

    for integer, factors in factor_dictionary.items():
        vector = [int(integer ** 2 - n < 0)] + [0] * len(factor_base)

        for prime, power in factors:
            index = prime_indices[prime] + 1
            vector[index] = power % 2

        integers.append(integer)
        vectors.append(vector)

    combination = find_square(vectors)

    selected_integers = [integers[i] for i in combination]
    x = math.prod(selected_integers) % n

    product = math.prod(integer ** 2 - n for integer in selected_integers)
    y = math.isqrt(product) % n

    factor_1 = math.gcd(x - y, n)
    factor_2 = math.gcd(x + y, n)

    if 1 < factor_1 < n:
        return factor_1, n // factor_1

    if 1 < factor_2 < n:
        return factor_2, n // factor_2

    return "No factors found for the given range and smoothness bound."
