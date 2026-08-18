import numpy as np
import itertools
import math


def generate_matrices(dim, n):
    return [np.array(matrix).reshape(dim, dim) for matrix in
            itertools.product(range(n), repeat=dim * dim)]

def GL(dim, n):
    GL = []
    for x in generate_matrices(dim, n):
        det = round(np.linalg.det(x)) % n
        if math.gcd(det, n) == 1:
            GL.append(x)
    return GL

def size(dim, n):
    coprime_set = [x for x in range(1, n) if math.gcd(x, n) == 1]
    prod = 1
    for i in range(0, dim):
        prod *= (n**dim - n**i)
    return prod

def determinant(matrix: np.ndarray) -> int:
    if not isinstance(matrix, np.ndarray):
        raise TypeError('Matrix must be a numpy array.')
    det = np.linalg.det(matrix)
    # Avoid floating point precision errors.
    if math.isclose(det, round(det)):
        return round(det)
    else:
        return det

def adjugate(matrix: np.ndarray) -> np.ndarray:
    if not isinstance(matrix, np.ndarray):
        raise TypeError('Matrix must be a numpy array.')
    rows, cols = matrix.shape
    cofactor_matrix = np.zeros_like(matrix, dtype=float)
    for i in range(rows):
        for j in range(cols):
            minor_matrix = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            cofactor_matrix[i, j] = (-1)**(i+j) * determinant(minor_matrix)
    return np.transpose(cofactor_matrix)

def mod_matrix_inverse(matrix: np.ndarray, mod: int) -> np.ndarray:
    if not isinstance(matrix, np.ndarray):
        raise TypeError('Matrix must be a numpy array.')
    if not isinstance(mod, int):
        raise TypeError('Modulus must be an integer.')
    det = determinant(matrix)
    if det == 0:
        raise ValueError('Matrix determinant is zero.')
    det = det % mod
    if det == 0:
        raise ValueError(f'Matrix determinant is zero mod {mod}.')
    if math.gcd(det, mod) != 1:
        raise ValueError(f'Determinant must be coprime with modulus.')
    mod_det_inv = pow(det, -1, mod)
    adj = adjugate(matrix)
    inv_matrix = (mod_det_inv * adj) % mod
    return inv_matrix.astype(int)

list = []
for x in GL(2,2):
    list.append(x.tolist())
for x in list:
    for row in x:
        print(row)
    print()

print("gap")

list2 = []
for x in list:
    list2.append(mod_matrix_inverse(np.array(x), 4))
for x in list2:
    print(x)
    print()

print(len(list))
print(len(list2))
print(size(2,2))
