import math


"""
The deduction of this file is an optimal value that occurs in cryptanalysis
of caesar encrypted plaintexts. 

The precise variable being optimised is the power to which the density of 
a given letter in English and in the given plaintext is raised to when their 
difference is taken, from which the most likely shift can be deduced as the 
shift with smallest distance from an ordinary distribution of letters function.
 
This is proven mathematically and shown to agree with the empirical value 
obtained by analysis long encrypted plaintexts.
"""

alphabet = "abcdefghijklmnopqrstuvwxyz"

freq_list = ["e", "t", "a", "o", "i", "n", "s", "h", "r", "d", "l", "c", "u",
             "m", "w", "f", "g", "y", "p", "b", "v", "k", "j", "x", "q", "z"]

density_list = [0.12702, 0.09056, 0.08167, 0.07507, 0.06966, 0.06749, 0.06327,
                0.06094, 0.05987, 0.0423, 0.04025, 0.02782, 0.02758, 0.02406,
                0.0236, 0.0228, 0.02015, 0.01974, 0.01929, 0.01492, 0.00978,
                0.00772, 0.00153, 0.0015, 0.00095, 0.00074]


def caesar_decrypt(ciphertext: str, key: int) -> str:
    plaintext = ''
    for letter in ciphertext:
        if letter in alphabet:
            # Shift the letter back by 'key' places.
            plaintext += alphabet[(alphabet.index(letter) - key) % 26]
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
        distance_sum += abs((density_list[i])**0.25
                            - (text.count(freq_list[i]) / len(text))**0.25)
    return distance_sum


def caesar_cryptanalysis(ciphertext: str) -> tuple[int, str]:
    """
    Cycle though each caesar decryption for every key.
    Return the text with the most normal distribution of letters.
    Defining most normal as the text with the lowest distance value.
    """
    distances = []
    for index in range(len(alphabet)):
        distances.append(distance(caesar_decrypt(ciphertext, index)))
    correct_key = distances.index(min(distances))
    return correct_key, caesar_decrypt(ciphertext, correct_key)


print(caesar_cryptanalysis('byffi qilfx! c ug u nymn gymmuay.'))


# Determination of the value of 0.25 for the power in the distance function :

def precision(text: str) -> float:
    """
    The precision measures the difference between the distance of a text
    and the average distance of the text averaged over 25 Caesar ciphers.
    This should be large, to represent the large difference in the distribution
    of letters between an ordinary text and encrypted texts
    """
    density_sum = 0
    density = distance(text)
    for i in range(1, 26):
        density_sum += distance(caesar_decrypt(text, i))
    average = density_sum/25
    return average - density


"""
For a given message we may consider different distance functions,
with different values of parameter x, instead of 0.25, as the power. 
We may then vary x and see which values provide optimal precision.
"""


# Doing so with the following messages :

message1 = ("Hello World! I am a test message to demonstrate that this "
            "analysis can work")

message2 = ("This is going to be a second test message to see where the new"
            " optimal exponent becomes.")

message3 = ("The European languages are members of the same family. Their "
            "separate existence is a myth. For science, music, sport, etc, "
            "Europe uses the same vocabulary. The languages only differ in"
            " their grammar, their pronunciation and their most common words. "
            "Everyone realizes why a new common language would be "
            "desirable:one could refuse to pay expensive translators. "
            "To achieve this, it would be necessary to have uniform grammar,"
            " pronunciation and more common words. If several languages "
            "coalesce, the grammar of the resulting language is more simple "
            "and regular than that of the individual languages. The new "
            "common language will bemore simple and regular than the existing"
            " European languages. It will be as simple as Occidental; in "
            "fact,it will be Occidental. To an English person, it will seem"
            " like simplified English, as a skeptical Cambridge friend of"
            " mine told me what Occidental is.")

message4 = ("In today’s digital world, content creation, web design, and"
            " software testing often require the use of placeholder text"
            " or sample data. This is where a Random Long Text Generator "
            "comes into play. A Random Long Text Generator is a tool that "
            "automatically generates large blocks of text, often in random "
            "order or following a specific pattern, which can be used for"
            " various purposes such as website design, app development, "
            "content creation, and software testing. Whether you’re a web "
            "developer needing text to populate a mockup, a writer looking "
            "for inspiration, or a data analyst testing input processing in "
            "software, a random long text generator offers a simple yet "
            "powerful solution. These tools allow users to create long "
            "strings of text quickly and easily, saving both time and "
            "effort.In this article, we’ll explore the key features of "
            "random long text generators, their various applications, "
            "the benefits they offer, and how to choose the best one"
            " for your needs. By the end, you’ll have a better understanding"
            " of how these generators work and how they can help streamline"
            " your work processes. A Random Long Text Generator is a tool "
            "or software that automatically creates long sequences of text,"
            " often without any specific meaning, based on randomized "
            "characters or predefined patterns. The generated text can vary"
            " in length and complexity, ranging from a few paragraphs to "
            "entire documents. These generators are primarily used for "
            "testing, prototyping, and placeholder purposes. Lorem ipsum"
            " is a pseudo-Latin text used in web design, typography, layout,"
            " and printing in place of English to emphasise design elements "
            "over content. It's also called placeholder (or filler) text. "
            "It's a convenient tool for mock-ups. It helps to outline the"
            " visual elements of a document or presentation, eg typography,"
            " font, or layout. Lorem ipsum is mostly a part of a Latin text"
            " by the classical author and philosopher Cicero. Its words and"
            " letters have been changed by addition or removal, so to "
            "deliberately render its content nonsensical; it's not genuine,"
            " correct, or comprehensible Latin anymore. While lorem ipsum's"
            " still resembles classical Latin, it actually has no meaning"
            " whatsoever. As Cicero's text doesn't contain the letters K,"
            " W, or Z, alien to latin, these, and others are often inserted"
            " randomly to mimic the typographic appearance of European "
            "languages, as are digraphs not to be found in the original."
            " In a professional context it often happens that private or"
            " corporate clients corder a publication to be made and presented"
            " with the actual content still not being ready. Think of a news"
            " blog that's filled with content hourly on the day of going "
            "live. However, reviewers tend to be distracted by comprehensible"
            " content, say, a random text copied from a newspaper or the "
            "internet. The are likely to focus on the text, disregarding "
            "the layout and its elements. Besides, random text risks to be"
            " unintentionally humorous or offensive, an unacceptable risk in"
            " corporate environments. Lorem ipsum and its many variants have"
            " been employed since the early 1960ies, and quite likely since "
            "the sixteenth century.")


# We have the following optimal values for x and their precision results :

optimal_value1 = 0.24
peak_precision1 = 2.275411805574244
optimal_value2 = 0.25
peak_precision2 = 2.044514717441647
optimal_value3 = 0.245
peak_precision3 = 2.5738808491817045
optimal_value4 = 0.25
peak_precision4 = 2.62978827490456

# The optimal value is consistently around 0.24 - 0.25.


"""
This problem may be treated mathematically, to optimise we may differentiate 
the precision function with respect to x then set this expression equal to zero 
and solve for x to find the optimum precision.

If our message is very long, with a close to typical distribution of letters,
the distance approaches zero. Hence, in this case, the precision will be equal
to only the sum of distance of the 25 Caesar shifted texts :
"""

# distance function with explicit dependence upon x.


def distance_x(text: str, x: float) -> float:
    distance_sum = 0
    for letter in range(1, 26):
        distance_sum += abs((density_list[letter])**x
                            - (text.count(freq_list[letter])/len(text))**x)
    return distance_sum


# A precision function, built upon the above distance function.

def precision_x(text: str, x: float) -> float:
    precision_x_sum = 0
    for shift in range(1, 26):
        precision_x_sum += distance_x(caesar_decrypt(text, shift), x)
    average = precision_x_sum/25
    return average


"""
For a large message with letter densities close to the correct densities,
we have that caesar_encrypt(text, shift).count(freq_list[letter]) / len(text)
=  density_list[letter - shift  mod 26]

This expresses the fact that the density of a letter in a Caesar shifted text
is equal to the density of the original letter that is shifted to that letter's
place, in the original text.

With this, we can derive a precision function independent of the message:
"""


def independent_precision(x: float) -> float:
    independent_precision_sum = 0
    for letter in range(0, 26):
        for shift in range(1, 26):
            independent_precision_sum += abs((density_list[letter])**x
                                             - (density_list[letter
                                                             - shift % 26])**x)
    return independent_precision_sum/25


"""
We see the precision function is now solely dependent on the set of densities.

To differentiate this expression with respect to x the absolute value must
be removed.

By considering the cases when the absolute value is negative and positive in 
the above expression, using induction on alphabets of different sizes, n,
we derive the following combinatorial expression for the precision:
"""


def precision_n(n: int, x: float) -> float:
    sum_n = 0
    for i in range(0, 26):
        sum_n += (2*(n-1) - 4*i) * density_list[i]**x
    return sum_n/(n-1)


# In our case we have an alphabet of length n = 26 :

def precision_26(x: float) -> float:
    sum_26 = 0
    for i in range(0, 26):
        sum_26 += (50 - 4*i) * density_list[i]**x
    return sum_26/25


# Taking the derivative of this expression with respect to x we have :


def derivative_precision_26(x: float) -> float:
    derivative_sum = 0
    for i in range(0, 26):
        derivative_sum += ((50 - 4*i) * density_list[i]**x
                           * math.log(density_list[i]))
    return derivative_sum/25


"""
Solving derivative_precision_26(x) = 0 provides the optimised value of x.

Mathematically, this expression is similar to those occurring in other 
optimisation problems, also in statistical mechanics, such as Shannon entropy,
with an added weighting of (50 -4*i) and a power of x.

However, in this form the sum is difficult to solve for x, due to the large
number of x dependent terms.

Instead, building on the independent_precision function, the sum may be
written as the sum over all differences between densities :
"""


def set_spread(x: float, densities: tuple[float]) -> float:
    independent_precision_sum = 0
    for i in range(len(densities)):
        for j in range(len(densities)):
            independent_precision_sum += abs((densities[i]) ** x
                                             - (densities[j]) ** x)
    return independent_precision_sum/(len(densities)-1)


"""
This function is exactly equal to the independent_precision function when 
densities = density_list.

Here, the value of x is optimal when the set of densities**x is
optimally spread out over [0,1]. We may optimise the spread of the set by
optimising a spread function, S(x) = densities[n]**x - densities[0]**x.

Differentiating and equating to zero we have:
log(densities[n]) * densities[n]**x = log(densities[0]) * densities[0]**x

The solution to which is 
x = log(log(densities[0])/log(densities[n])) / log(densities[n] / densities[0])
"""


def optimal_x(densities: tuple[float]) -> float:
    x = (math.log((math.log(densities[0]) / math.log(densities[-1])))
         / (math.log(densities[-1] / densities[0])))
    return x


"""
For the set of alphabetic densities this formula gives 0.2431178.
Empirically the optimal value is 0.2495137, based on optimisation of 
the independent_precision function.

This completes the justification of the choice of 0.25 in the original
distance function.
"""
