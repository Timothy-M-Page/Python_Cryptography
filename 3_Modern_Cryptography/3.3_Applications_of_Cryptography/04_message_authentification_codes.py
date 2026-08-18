import hashlib


def sha_3_256(string: str) -> str:
    sha3_256_hash = hashlib.sha3_256(string.encode()).hexdigest()
    return sha3_256_hash


"""
A message authentication code (MAC) allows the authentication of a 
message's integrity.
 
A sender combines a message and a shared secret key by hashing 
them together. The message and MAC may then be send to a receiver.

A receiver may authenticate the MAC, by recalculating the MAC using 
the message and secret key, and comparing to the received hash.

This shows that the message cannot have been changed upon transmission
and that the sender must know the secret key.
"""


def mac(plaintext: str, secret_key: str) -> str:
    appended_plaintext = secret_key + plaintext
    hash_value = sha_3_256(appended_plaintext)
    return hash_value


def h_mac(plaintext: str, secret_key: str) -> str:
    """
    HMACs ensure greater security by further processing the key
    and combining the key and message through a two hash process.

    Form a 64 byte key by padding with zeros if too short,
    or hashing to 32 bytes, then padding with zeros, if too long.

    XOR this key with 0x36, and with 0x5C, to form key1 and key2.

    Concatenate key1 with the message, and hash this to form hash1.
    Concatenate key2 with the hash1, and hash this to form the HMAC.
    """
    key = secret_key.encode()
    if len(key) < 64:
        key = key.ljust(64, b'\x00')
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
        key = key.ljust(64, b'\x00')

    key1 = bytes([k ^ 0x36 for k in key])
    key2 = bytes([k ^ 0x5C for k in key])

    hash1 = hashlib.sha256(key1 + plaintext.encode()).digest()
    hash2 = hashlib.sha256(key2 + hash1).hexdigest()
    return hash2


def mac_verification(plaintext: str, key: str, expected_hash: str) -> str:
    generated_hash_value = mac(plaintext, key)
    if generated_hash_value == expected_hash:
        return 'MAC is valid.'
    else:
        return 'MAC is invalid.'


def h_mac_verification(plaintext: str, key: str, expected_hash: str) -> str:
    generated_hash_value = h_mac(plaintext, key)
    if generated_hash_value == expected_hash:
        return 'HMAC is valid.'
    else:
        return 'HMAC is invalid.'
