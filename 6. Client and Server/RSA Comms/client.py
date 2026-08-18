import os
from socket import socket

import aes_gcm
import message_format
import rsa_functions
import digital_signature

# -----------------------------------------------------------------------------

IP = '127.0.0.1'
PORT = 8085

sock = socket()
sock.connect((IP, PORT))


e_len = int.from_bytes(sock.recv(4), "big")
e = int.from_bytes(sock.recv(e_len), "big")

n_len = int.from_bytes(sock.recv(4), "big")
n = int.from_bytes(sock.recv(n_len), "big")

sig_len = int.from_bytes(sock.recv(4), "big")
signature = int.from_bytes(sock.recv(sig_len), "big")

print("Public key received.")

public_key = (e, n)


e_bytes = e.to_bytes((e.bit_length()+7)//8, "big")
n_bytes = n.to_bytes((n.bit_length()+7)//8, "big")

valid = digital_signature.rsa_verify(e_bytes + n_bytes, signature, e, n)

if not valid:
    print("Server authentication Failed.")
    sock.close()
    exit()

print("Server signature verified.")


aes_key, encapsulated_seed = rsa_functions.create_and_encapsulate_key(e, n)
print("AES key seed created.")
print("AES key created.")


cipher_bytes = encapsulated_seed.to_bytes((encapsulated_seed.bit_length()+7) // 8, "big")
sock.sendall(len(cipher_bytes).to_bytes(4, "big"))
sock.sendall(cipher_bytes)
print("AES key seed sent to server.")


server_ip, server_port = sock.getpeername()
print(f"Connected to server at {server_ip}:{server_port}")
print("Type 'quit to terminate the connexion.")
print()


client_message = ''
while client_message != '`quit':
    client_message = input("You: ")
    encoded_client_message = client_message.encode()

    nonce = os.urandom(12)
    ciphertext, tag = aes_gcm.aes_encrypt_gcm(encoded_client_message, aes_key, nonce)

    message_format.send_packet(sock, nonce, tag, ciphertext)

    packet = message_format.recv_packet(sock)
    if packet is None:
        break

    nonce, tag, ciphertext = packet
    plaintext = aes_gcm.aes_decrypt_gcm(ciphertext, tag, aes_key, nonce)

    server_message = plaintext.decode().rstrip('\n')
    print(f"Server: {server_message}")


sock.close()
print("Thankyou for using cryptographically secure services, have a nice day!")
