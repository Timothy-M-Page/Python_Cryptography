

def kasiski_exam(text: str, mod: int) -> list[str]:
    """
    The Kasiski exam returns the characters of a text that
    occur in congruent positions modulus mod.
    """
    congruent_strings = []
    for i in range(mod):
        string_i = ''.join(text[j] for j in range(len(text)) if j % mod == i)
        congruent_strings.append(string_i)
    return congruent_strings
