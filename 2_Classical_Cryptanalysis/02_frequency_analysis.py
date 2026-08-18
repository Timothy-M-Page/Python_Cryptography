import itertools

ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

ENGLISH_K_GRAM_FREQUENCIES = [
   [['e', 0.12702], ['t', 0.09056], ['a', 0.08167], ['o', 0.07507],
    ['i', 0.06966], ['n', 0.06749], ['s', 0.06327], ['h', 0.06094],
    ['r', 0.05987], ['d', 0.04253], ['l', 0.04025], ['c', 0.02782],
    ['u', 0.02758], ['m', 0.02406], ['w', 0.02360], ['f', 0.02228],
    ['g', 0.02015], ['y', 0.01974], ['p', 0.01929], ['b', 0.01492],
    ['v', 0.00978], ['k', 0.00772], ['j', 0.00153], ['x', 0.00150],
    ["q", 0.00095], ["z", 0.00074]],

   [['th', 0.0356], ['he', 0.0307], ['in', 0.0243], ['en', 0.0205],
    ['nt', 0.0199], ['re', 0.0185], ['er', 0.0176], ['an', 0.0149],
    ['ti', 0.0145], ['es', 0.0135], ['on', 0.013], ['at', 0.013],
    ['se', 0.012], ['nd', 0.012], ['or', 0.011], ['ar', 0.011],
    ['al', 0.010], ['te', 0.010], ['co', 0.010], ['de', 0.010]],

   [['the', 0.016], ['and', 0.008], ['tha', 0.007], ['ent', 0.007],
    ['ing', 0.006], ['ion', 0.006], ['tio', 0.005], ['for', 0.005],
    ['nde', 0.004], ['has', 0.004], ['nce', 0.004], ['edt', 0.004],
    ['tis', 0.004], ['oft', 0.003], ['sth', 0.003], ['men', 0.003]]]


def most_frequent_k_grams(text: str, k: int) -> list:
    DECIMAL_PLACE = 3
    LIST_LENGTH = 5
    length = len(text)
    all_i_grams = [''.join(comb) for comb in
                   itertools.product(ALPHABET, repeat=k)]
    frequency_list = []
    for i_gram in all_i_grams:
        i_gram_count = text.count(i_gram)
        entry = [i_gram, round(i_gram_count / (length - k + 1), DECIMAL_PLACE)]
        frequency_list.append(entry)
    frequency_list.sort(key=lambda x: x[1], reverse=True)

    return frequency_list[:LIST_LENGTH]
