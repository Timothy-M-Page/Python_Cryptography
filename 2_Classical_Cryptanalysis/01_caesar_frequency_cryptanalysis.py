ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

FREQ_LIST = ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c', 'u',
             'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z']

DENSITY_LIST = [0.12702, 0.09056, 0.08167, 0.07507, 0.06966, 0.06749, 0.06327,
                0.06094, 0.05987, 0.0423, 0.04025, 0.02782, 0.02758, 0.02406,
                0.0236, 0.0228, 0.02015, 0.01974, 0.01929, 0.01492, 0.00978,
                0.00772, 0.00153, 0.0015, 0.00095, 0.00074]


def caesar_decrypt(ciphertext: str, key: int) -> str:
    ciphertext = ciphertext.lower()
    plaintext = ''
    for letter in ciphertext:
        if letter in ALPHABET:
            # Shift the letter back by 'key' places.
            plaintext += ALPHABET[(ALPHABET.index(letter) - key)
                                  % len(ALPHABET)]
        else:
            plaintext += letter
    return plaintext


def distance(text: str) -> float:
    """
    Measures how far a text is from a typical distribution of letters.
    A sum of differences between text densities and normal densities.
    """
    distance_sum = 0
    for i in range(26):
        distance_sum += abs((DENSITY_LIST[i])**0.25
                            - (text.count(FREQ_LIST[i]) / len(text))**0.25)
    return distance_sum


def caesar_cryptanalysis(ciphertext: str) -> tuple[int, str]:
    """
    Cycle though each caesar decryption for every key.
    Return the text with the most normal distribution of letters.
    Defining most normal as the text with the lowest distance value.
    """
    ciphertext = ciphertext.lower()
    distances = []
    for index in range(len(ALPHABET)):
        distances.append(distance(caesar_decrypt(ciphertext, index)))
    correct_key = distances.index(min(distances))
    return correct_key, caesar_decrypt(ciphertext, correct_key)

