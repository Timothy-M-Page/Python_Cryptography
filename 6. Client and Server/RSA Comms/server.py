import os
import socket

import aes_gcm
import message_format
import rsa_functions
import digital_signature

public, private = rsa_functions.generate_key_pair(2048)

# -----------------------------------------------------------------------------

IP = '127.0.0.1'
PORT = 8085

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = (IP, PORT)

server_socket.bind(server_address)

server_socket.listen(1)
print(f"Server listening on {IP}:{PORT}.")


# -----------------------------------------------------------------------------


while True:
    connection, client_address = server_socket.accept()
    print(f"Connection from {client_address}.")
    print()

    pub_e, pub_n = public

    e_bytes = pub_e.to_bytes((pub_e.bit_length() + 7) // 8, "big")
    n_bytes = pub_n.to_bytes((pub_n.bit_length() + 7) // 8, "big")

    connection.sendall(len(e_bytes).to_bytes(4, "big"))
    connection.sendall(e_bytes)

    connection.sendall(len(n_bytes).to_bytes(4, "big"))
    connection.sendall(n_bytes)

    # Sign the public key
    signature = digital_signature.rsa_sign(e_bytes + n_bytes, private[0], private[1], private[2])

    sig_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, "big")
    connection.sendall(len(sig_bytes).to_bytes(4, "big"))

    connection.sendall(sig_bytes)

    print("Public key and signature sent.")

    cipher_len = int.from_bytes(connection.recv(4), "big")
    cipher_bytes = connection.recv(cipher_len)

    cipher_seed = int.from_bytes(cipher_bytes, "big")

    print("Encapsulated seed received.")

    prime_a, prime_b, priv_exponent = private
    aes_key = rsa_functions.decapsulate_and_create_key(cipher_seed, prime_a, prime_b, priv_exponent, pub_n)

    print("AES key derived.")
    print("Communication channel open and secured.")
    print()

    client_message = ''
    while client_message != '`quit':

        packet = message_format.recv_packet(connection)
        if packet is None:
            break

        nonce, tag, ciphertext = packet
        plaintext = aes_gcm.aes_decrypt_gcm(ciphertext, tag, aes_key, nonce)

        client_message = plaintext.decode().rstrip('\n')
        print(f"Client: {client_message}")

        if client_message == '`quit':
            break

        server_message = input("You: ")
        encoded_client_message = server_message.encode()

        nonce = os.urandom(12)
        ciphertext, tag = aes_gcm.aes_encrypt_gcm(encoded_client_message, aes_key, nonce)

        message_format.send_packet(connection, nonce, tag, ciphertext)

    connection.close()

