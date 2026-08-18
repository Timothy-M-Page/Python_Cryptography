import math
import random
import numpy as np


def determinant(matrix: np.ndarray) -> int:
    det = np.linalg.det(matrix)
    if math.isclose(det, round(det)):
        return int(round(det))
    else:
        return int(det)


def adjugate(matrix: np.ndarray) -> np.ndarray:
    rows, cols = matrix.shape
    cofactor_matrix = np.zeros_like(matrix, dtype=float)
    for i in range(rows):
        for j in range(cols):
            minor_matrix = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            cofactor_matrix[i, j] = (-1)**(i+j) * determinant(minor_matrix)
    return np.transpose(cofactor_matrix)


def mod_matrix_inverse(matrix: np.ndarray, mod: int) -> np.ndarray:
    det = determinant(matrix)
    det = det % mod
    mod_det_inv = pow(det, -1, mod)
    adj = adjugate(matrix)
    inv_matrix = (mod_det_inv * adj) % mod
    return inv_matrix.astype(int)


def generate_error_vector(code_length: int, weight: int) -> np.array:
    error_vector = [0] * code_length
    ones_positions = random.sample(range(code_length), k=min(weight, code_length))
    for pos in ones_positions:
        error_vector[pos] = 1
    return np.array(error_vector)


def random_invertible_matrix(dimension: int) -> np.array:
    while True:
        M = np.random.randint(0, 2, (dimension, dimension), dtype=int)
        if (determinant(M) % 2) != 0:
            return M


def generator_matrix(message_length: int, redundancy_length: int) -> np.array:
    I = np.identity(message_length, dtype=int)
    A = np.random.randint(0, 2, (message_length, redundancy_length))
    return np.concatenate((I, A), axis=1)


def deduce_parity_check_matrix(generator: np.array) -> np.array:

    # Make a copy
    G = [row[:] for row in generator]

    m = len(G)
    n = len(G[0])

    pivots = []
    row = 0

    for col in range(n):
        # Find pivot
        pivot = None
        for r in range(row, m):
            if G[r][col] == 1:
                pivot = r
                break

        if pivot is None:
            continue

        # Swap rows
        G[row], G[pivot] = G[pivot], G[row]
        pivots.append(col)

        # Eliminate other rows
        for r in range(m):
            if r != row and G[r][col] == 1:
                # XOR rows
                G[r] = [(a ^ b) for a, b in zip(G[r], G[row])]

        row += 1
        if row == m:
            break

    free_cols = [c for c in range(n) if c not in pivots]

    basis = []

    for free in free_cols:
        vec = [0] * n
        vec[free] = 1

        # Back-substitution
        for i in reversed(range(len(pivots))):
            pivot_col = pivots[i]
            if G[i][free] == 1:
                vec[pivot_col] = 1

        basis.append(vec)

    return basis


def generate_keys_and_error_vector(generator: np.array, code_length: int, weight: int) -> tuple:
    dimension1 = len(generator)
    dimension2 = len(generator[0])

    scrambling_matrix = random_invertible_matrix(dimension1)
    permutation_matrix = random_invertible_matrix(dimension2)

    public_key = (scrambling_matrix @ generator @ permutation_matrix) % 2
    private_key = (scrambling_matrix, generator, permutation_matrix)
    error_vector = generate_error_vector(code_length, weight)

    return public_key, private_key, error_vector


def mceliece_encrypt(plaintext: bytes, public_key: tuple, error_vector: np.array) -> np.array:
    bit_message = np.unpackbits(np.frombuffer(plaintext, dtype=np.uint8))
    return ((bit_message @ public_key) + error_vector) % 2


def mceliece_decrypt(ciphertext: np.array, private_key: tuple, error_vector: np.array, message_length: int) -> bytes:

    scrambling_inverse = mod_matrix_inverse(private_key[0], 2)
    permutation_inverse = mod_matrix_inverse(private_key[2], 2)
    parity_check_matrix = deduce_parity_check_matrix(private_key[1])

    u = (ciphertext @ permutation_inverse) % 2
    v = parity_check_matrix @ u.T

    # Would ideally use v to find the permuted error vector P.e via a lookup
    # table.

    # permuted_error_vector = look_up_table(v)

    # Or in practice use codes with a specific structure such as Goppa codes
    # that allow efficient decoding without the need of a large look-up table.

    permuted_error_vector = (error_vector @ permutation_inverse) % 2
    corrected_u = ((u + permuted_error_vector) % 2)[:message_length]

    bits = (corrected_u @ scrambling_inverse) % 2

    return int(''.join(map(str, bits)), 2).to_bytes(1, 'big')


G1 = generator_matrix(8, 3)
x = generate_keys_and_error_vector(G1, 11, 1)
y = mceliece_encrypt(b'h', x[0], x[2])
z = mceliece_decrypt(y, x[1], x[2], 8)
print(z)
