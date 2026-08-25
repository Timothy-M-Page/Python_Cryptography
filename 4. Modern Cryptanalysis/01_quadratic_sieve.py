import math

"""
If N = pq is the modulus in RSA then we may find factors of N by solving
x**2 - y**2 == 0 mod(N).
In such a case it follows N divides x**2 - y**2 = (x-y)(x+y).

Provided x != ±y mod(N), N cannot divide each factor (x∓y), thus it's factors
must split between the two terms.

So we wish to find x**2 - y**2 = 0 mod(N) then find gcd(x,N) and gcd(y,N).
Since the factors of N split and N = pq these two factors must be p and q.

In this file we implement 3 versions of this

1. A basic solution to x**2 mod N = y**2.

2. Solutions to x**2 - N == y**2 mod(N) up to a given smoothness bound
   then combine solutions using index calculus on the resulting powers
   mod 2 to reconstruct a square.
   
3. Solutions to x**2 == N mod(p) for every prime p in the factor base (sieve).
   Use these solutions to find the primes dividing x**2 - N, then factor the 
   resulting values over the factor base, and combine the resulting vectors 
   mod 2 to find a square.
"""


def very_basic_quad_sieve(n: int) -> list[int]:
    start = math.ceil(math.sqrt(n))
    end = 2*start

    for integer in range(start, end):
        square = integer**2 % n

        if math.isqrt(square)**2 == square:
            root = math.isqrt(square)

            factor = math.gcd(n, integer - root)

            if 1 < factor < n:
                return [factor, n // factor]


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


def primes_up_to(x: int) -> list[int]:
    primes = []
    for n in range(2, x + 1):
        if all(n % p != 0 for p in primes if p * p <= n):
            primes.append(n)
    return primes


def quad_residue_primes_up_to(x: int, n: int) -> list[int]:
    """
    The only primes we need to consider are those up to the smoothness bound,
    since we are checking for p dividing x**2 - n, the prime in question must
    be a quadratic residue, hence we may also filter out those that are not.
    """
    primes = primes_up_to(x)

    return [p for p in primes if p == 2 or is_quadratic_residue(n, p)]


def p_adic_valuation(p: int, n: int) -> int:
    count = 0
    n = abs(n)
    while n % p == 0:
        count += 1
        n //= p
    return count


def find_square(vectors: list[list[int]]) -> list[int] | None:
    pivots = {}
    for i, vector in enumerate(vectors):
        value = 0
        for j, bit in enumerate(vector):
            if bit:
                value |= (1 << j)

        combination = (1 << i)

        while value:
            pivot = value.bit_length() - 1

            if pivot not in pivots:
                pivots[pivot] = (value, combination)
                break

            pivot_value, pivot_combination = pivots[pivot]

            value ^= pivot_value
            combination ^= pivot_combination

        if value == 0:
            return [i for i in range(len(vectors)) if combination & (1 << i)]

    return None


def modular_quad_sieve(n: int, smooth_bound: int, search_range: int) -> tuple[int, int] | str:
    start = math.ceil(math.sqrt(n))
    factor_base = quad_residue_primes_up_to(smooth_bound, n)
    smooth_numbers = []
    vectors = []

    for integer in range(start - search_range, start + search_range):
        square = (integer**2 - n)
        factorisation = prime_factors(square)

        smooth = all(p in factor_base for p, _ in factorisation)

        if smooth:
            smooth_numbers.append(integer)
            power_vector = ([int(square < 0)] +
                            [p_adic_valuation(p, square) % 2
                             for p in factor_base])
            vectors.append(power_vector)

    combination = find_square(vectors)

    square_generators = [smooth_numbers[i] for i in combination]

    square_1 = math.prod(square_generators) % n
    product = math.prod(integer ** 2 - n for integer in square_generators)
    square_2 = math.isqrt(abs(product)) % n

    factor_1 = math.gcd(square_1 - square_2, n)
    factor_2 = math.gcd(square_1 + square_2, n)

    if 1 < factor_1 < n:
        return factor_1, n // factor_1

    if 1 < factor_2 < n:
        return factor_2, n // factor_2

    return "No factors found for the given smoothness bound and range."


def quad_sieve(n: int, smooth_bound: int, search_range: int) -> tuple[int, int] | str:
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
