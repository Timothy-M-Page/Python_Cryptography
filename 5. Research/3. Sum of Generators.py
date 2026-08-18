import math

from typing import Union
from sympy import isprime
import matplotlib.pyplot as plt


class GroupMod:
    def __init__(self, mod: int):
        self.mod = mod
        # Form the set of integers less than and coprime to n, to form a group.
        self.group = sorted([x for x in range(1, mod)
                             if math.gcd(x, mod) == 1])

    def product(self, x: int, y: int):
        return (x * y) % self.mod

    def inverse(self, x: int):
        if math.gcd(x, self.mod) != 1:
            return f'{x} has no inverse mod {self.mod}.'
        return pow(x, -1, self.mod)

    def exponent(self, x: int, n: int):
        """
        Returns the exponent in O(log_2(n)) calculations.
        The exponent is written as a binary string.
        A list stores x to successive powers of 2.
        The power is calculated using these powers and the binary string.
        """
        binary = bin(n)[2:][::-1]
        powers = [x]
        for x in range(1, len(binary)):
            powers.append((powers[-1] ** 2) % self.mod)
        result = 1
        for index in range(len(binary)):
            if binary[index] == '1':
                result = result * powers[index] % self.mod
        return result

    def discrete_log(self, b: int, x: int):
        exponent = b % self.mod
        for i in range(1, len(self.group) + 1):
            if exponent == x:
                return i
            exponent = (exponent * b) % self.mod
        return f'There is no solution to {b}**n = {x} (mod {self.mod}).'

    def subgroup(self, x: int):
        sub = []
        exponent = x
        for i in range(1, len(self.group)):
            if exponent not in sub:
                sub.append(exponent)
            exponent = (exponent * x) % self.mod
        return sub

    def order(self, x: int):
        return self.discrete_log(x, 1)

    def generators(self) -> Union[list[int], str]:
        gen = []
        for g in self.group:
            if self.order(g) == self.mod - 1:
                gen.append(g)
        if not gen:
            return f'The group mod {self.mod} has no generators.'
        return gen

    def print_group(self) -> list[int]:
        return self.group


def gsm(s: int, a: int, b: int) -> list[int]:
    """
    Sum the difference between the number of generators of Z/pZ and the nearest
    multiple of p. This is sum(gen(Z/pZ)) % p This is always -1,0,1 (prove plz)
    """
    generator_sum_modulus = s
    iterative_sum_values = []
    for x in range(a, b):
        if isprime(x):
            G = GroupMod(x).generators()
            if sum(G) % x > 1:
                print(x, round(sum(G) / x), (sum(G) % x) - x)
                y = generator_sum_modulus
                generator_sum_modulus -= 1
                iterative_sum_values.append(generator_sum_modulus)
            else:
                print(x, round(sum(G) / x), sum(G) % x)
                y = generator_sum_modulus
                generator_sum_modulus += (sum(G) % x)
                iterative_sum_values.append(generator_sum_modulus)

    return iterative_sum_values


values = [1, 0, 0, 1, 2, 2, 2, 2, 3, 3, 2, 2, 2, 1, 2, 2, 3, 3, 2, 1, 1, 0, 1, 1, 1]


def graph(points: list[int]):
    # Curve details
    plt.plot(points, marker='.', linestyle='-', color='g')

    # Make the axes cross at (0, 0)
    plt.axhline(0, color='black', linewidth=1)
    plt.axvline(0, color='black', linewidth=1)

    # Set graph boundaries
    plt.xlim(0, len(points))
    plt.ylim(-10, 10)

    plt.grid(True)

    plt.title('Sum of generators mod p sum')
    plt.xlabel('Index of prime number')
    plt.ylabel('Sum')

    # Print a graph
    plt.show()

graph(values)
