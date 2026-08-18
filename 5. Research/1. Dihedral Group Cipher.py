

"""
Dihedral group n is the set of symmetries on a n sided regular polygon.
This group has size 2n and is composed of n rotations and n reflections.

The class below models this group using the integers 0 to 2n-1 and modular
arithmetic to recreate the group structure of the dihedral group with
numbers as elements. 0 to n-1 = Rotations and n to 2n - 1 reflections
"""


class DihedralGroup:
    def __init__(self, n: int):
        self.n = n
        self.group = [x for x in range(0, (2 * n))]

    def product(self, x: int, y: int) -> int:
        if x < self.n and y < self.n:
            return (x + y) % self.n
        if x < self.n <= y:
            return self.n + ((x + y) % self.n)
        if y < self.n <= x:
            return self.n + ((x - y) % self.n)
        if x >= self.n and y >= self.n:
            return (x - y) % self.n

    def inverse(self, x: int) -> int:
        if x >= self.n:
            return x
        if x < self.n:
            return (self.n - x) % self.n

    def print_group(self) -> list[int]:
        return self.group


n = 5
print(DihedralGroup(n).print_group())
print(DihedralGroup(n).product(7,8))
print(DihedralGroup(n).inverse(2))


"""
This may be turned into a cipher by taking any cipher using Z/nZ with 
modular multiplication, and substituting the Dihedral group in its place.
"""