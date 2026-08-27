import math
from itertools import combinations

"""
Given a number to factor n, we find an algebraic field, K, homomorphic to
the set Z/nZ, with an ideal I, such that, if phi is the homomorphism,
phi(I) is a square in Z/nZ and I is a square ideal in K. In such a case:

x**2 = phi(I) = phi(J**2) = phi(J)**2 = y**2 mod(n).

From which, as in the quadratic sieve we may find the factors of n as 
gcd(n, x-y) and gcd(n, x+y).

Please note, this sieve was a lot harder and more pernickety than I could
have imagined when I started writing it. There are many points where the
following code makes simplifications, for example:

1. The optimum polynomial degree is (3 ln(N) / ln(ln(N)) ) ^ (1/3)
   we only look at quadratic fields, that is, where d = 2.

2. We work only with UFD's in the sieve implemented here. In practice for a 
   class group C(K) of size h_K, C(K) is isomorphic to Z/h_K Z, thus when
   finding squares at the end of the sieve, this process may be edited to
   find squares that also combine to produce a principal ideal.

3. We find the smooth ideals by looking at the primes dividing the norm, 
   however, as there are many ideals of the same norm, a square norm does
   not necessarily imply a square ideal.
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


def primes_up_to(x: int) -> list[int]:
    primes = []
    for n in range(2, x + 1):
        if all(n % p != 0 for p in primes if p * p <= n):
            primes.append(n)
    return primes


def optimal_smoothness_bound(n: int) -> int:
    exponent = (8/9)**(1/3) * (math.log(n)**(1/3)
                               * (math.log(math.log(n)))**(2/3))
    return math.ceil(math.exp(exponent))


def algebraic_factor_base(smooth_bound: int, root: int):
    """
    We represent the ideals in question here as [prime, r].
    As ideals these lists correspond to < prime, sqrt(root) - r >
    """
    primes = primes_up_to(smooth_bound)
    ideals = []
    for prime in primes:
        if is_quadratic_residue(root, prime):
            for r in range(prime):
                if (r**2 - root) % prime == 0:
                    ideals.append([prime, r])
    return ideals


def factor_principal_ideal(a: int, b: int, d: int):
    norm = abs(a**2 - d*b**2)
    rational_factors = prime_factors(norm)
    factors = []

    for p, exponent in rational_factors:
        roots = [r for r in range(p) if (r*r - d) % p == 0]
        for r in roots:
            if (a + b*r) % p == 0:
                factors.append((p, r, exponent))

    return factors


def is_mod_smooth(a: int, b: int, modulus: int, smooth_bound: int) -> bool:
    integer = a + b * modulus
    factors = prime_factors(integer)
    prime_base = primes_up_to(smooth_bound)

    if all(factors[i][0] in prime_base for i in range(len(factors))):
        return True

    return False


def is_alg_smooth(a: int, b: int, d: int, smooth_bound: int) -> bool:
    norm = abs(a**2 - d * b**2)
    factorisation = prime_factors(norm)

    for p, _ in factorisation:
        if p > smooth_bound:
            return False

        roots = [r for r in range(p) if (r*r - d) % p == 0]

        if len(roots) == 0:
            return False

        if not any((a + b*r) % p == 0 for r in roots):
            return False

    return True


def power_vector(a: int, b: int, root: int, m: int, factors_1: list[int],
                 factors_2: list[list[int]]) -> list[int]:

    alg_index = {(p, r): i for i, (p, r) in enumerate(factors_2)}

    vector = [0] * (1 + len(factors_1) + len(factors_2))

    if a + b * m < 0:
        vector[0] = 1
    else:
        vector[0] = 0

    modular_integer = abs(a + b * m)
    modular_factorisation = prime_factors(modular_integer)

    for p, exponent in modular_factorisation:
        index = factors_1.index(p) + 1
        vector[index] = exponent % 2

    algebraic_factorisation = factor_principal_ideal(a, b, root)

    for p, r, exponent in algebraic_factorisation:
        index = 1 + len(factors_1) + alg_index[(p, r)]
        vector[index] = exponent % 2

    return vector


def find_square(vectors: list[list[int]]) -> list[int] | None:
    for size in range(1, len(vectors) + 1):
        for combination in combinations(range(len(vectors)), size):

            result = [0] * len(vectors[0])

            for i in combination:
                result = [a ^ b for a, b in zip(result, vectors[i])]

            if all(bit == 0 for bit in result):
                return list(combination)

    return None


def multiply_ideals(ideals: list[tuple[int, int]], d: int) -> tuple[int, int]:
    result_a = 1
    result_b = 0

    for a, b in ideals:
        result_a, result_b = (result_a * a + d * result_b * b,
                              result_a * b + result_b * a)

    return result_a, result_b


def ideal_root(a: int, b: int, root: int) -> tuple[int, int] | None:
    norm = a**2 - root*b**2

    if norm < 0:
        return None

    norm_root = math.isqrt(norm)

    if norm_root**2 != norm:
        return None

    x2 = (a + norm_root) // 2
    dy2 = (a - norm_root) // 2

    if x2 >= 0 and dy2 % root == 0:
        y2 = dy2 // root

        x = math.isqrt(x2)
        y = math.isqrt(y2)

        if x*x == x2 and y*y == y2:
            return x, y

    x2 = (a - norm_root) // 2
    dy2 = (a + norm_root) // 2

    if x2 >= 0 and dy2 % root == 0:
        y2 = dy2 // root

        x = math.isqrt(x2)
        y = math.isqrt(y2)

        if x*x == x2 and y*y == y2:
            return x, y

    return None


def number_field_sieve(n: int, smooth_bound: int, search_range: int,
                       root: int, m: int) -> tuple[int, int] | str:

    """
    root and m should be chosen such that there is a homomorphism, phi, from
    Z[root(d)] an order of the ring of integers Z_K of the field K to the
    integers mod N.

    phi : Z[root(d)] -> Z/NZ
        : a + b.root(d) -> a + b.m
    """

    mod_factor_base = primes_up_to(smooth_bound)
    alg_factor_base = algebraic_factor_base(smooth_bound, root)

    candidates = [(a, b) for a in range(-search_range, search_range)
                  for b in range(1, search_range) if math.gcd(a, b) == 1]

    smooth_ints = [(a, b) for a, b in candidates
                   if is_mod_smooth(a, b, m, smooth_bound)
                   if is_alg_smooth(a, b, root, smooth_bound)]

    power_vectors = [power_vector(integer[0], integer[1], root, m,
                                  mod_factor_base, alg_factor_base)
                     for integer in smooth_ints]

    square_pieces = [smooth_ints[i] for i in find_square(power_vectors)]

    ideal_1 = multiply_ideals(square_pieces, root)
    ideal_2 = ideal_root(ideal_1[0], ideal_1[1], root)

    if ideal_2 is None:
        return f"Square ideal pieces do not combine to give a square ideal."

    x = int(math.sqrt(ideal_1[0] + ideal_1[1] * m))
    y = ideal_2[0] + ideal_2[1] * m

    factor_1 = math.gcd(x - y, n)
    factor_2 = math.gcd(x + y, n)

    if 1 < factor_1 < n:
        return factor_1, n // factor_1

    if 1 < factor_2 < n:
        return factor_2, n // factor_2
