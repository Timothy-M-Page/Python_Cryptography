from sympy import randprime
import random


# Bob

prime = randprime(2**(2048-1), 2**2048)
base = random.getrandbits(2048)
bob_private_exponent = random.getrandbits(2048)

bobs_number = pow(base, bob_private_exponent, prime)

public_key = (prime, base, bobs_number)     # Send to Alice


# Alice

prime = public_key[0]
base = public_key[1]
bobs_number = public_key[2]

alice_private_exponent = random.getrandbits(2048)
ephemeral_key = pow(base, alice_private_exponent, prime)
masking_key = pow(bobs_number, alice_private_exponent, prime)

message = 1234

encrypted_message = (message * masking_key) % prime     # Send to Bob

alices_message = (ephemeral_key, encrypted_message)


# Bob 2

ephemeral_key = alices_message[0]
encrypted_message = alices_message[1]

masking_key = pow(ephemeral_key, bob_private_exponent, prime)

inverse_masking_key = pow(masking_key, -1, prime)
inverse_masking_key2 = pow(ephemeral_key, prime-bob_private_exponent-1, prime)
# This second form follows from Fermat's Little theorem, see Paar p265

decrypted_message = (encrypted_message * inverse_masking_key2) % prime

print(message)
print(encrypted_message)
print(decrypted_message)

