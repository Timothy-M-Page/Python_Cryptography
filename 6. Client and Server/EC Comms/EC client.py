import os
import socket
import struct
import secrets

import aes
import sha256
import message_format
import elliptic_curves


# -----------------------------------------------------------------------------


def point_to_bytes(point: tuple) -> bytes:
    x_bytes = point[0].to_bytes((point[0].bit_length() + 7) // 8, 'big')
    y_bytes = point[1].to_bytes((point[1].bit_length() + 7) // 8, 'big')
    return struct.pack('>I', len(x_bytes)) + x_bytes + struct.pack('>I', len(y_bytes)) + y_bytes


def bytes_to_point(data: bytes) -> tuple[int, int]:
    offset = 0
    x_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    x = int.from_bytes(data[offset:offset+x_len], 'big')
    offset += x_len
    y_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    y = int.from_bytes(data[offset:offset+y_len], 'big')
    return (x, y)


# -----------------------------------------------------------------------------


IP = '127.0.0.1'
PORT = 8085

sock = socket.socket()
sock.connect((IP, PORT))


# -----------------------------------------------------------------------------


identity = ("O", "O")


def p_521() -> tuple:
    p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    a = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
    b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00

    base_x = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
    base_y = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
    order = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

    return a, b, p, base_x, base_y, order


CURVE_PARAMETERS = (p_521()[0], p_521()[1], p_521()[2])
base_point = (p_521()[3], p_521()[4])
point_order = p_521()[5]


def derive_aes_key(shared_x: int, key_size: int = 32) -> bytes:
    shared_bytes = shared_x.to_bytes((shared_x.bit_length() + 7) // 8, 'big')
    return sha256.sha2(shared_bytes)[:key_size]


# -----------------------------------------------------------------------------


# Client key pair
client_private_key = secrets.randbelow(point_order - 1) + 1
client_public_key = elliptic_curves.point_exponent(CURVE_PARAMETERS, base_point, client_private_key)

print("Keys generated:")
print(f"client_private_key: {client_private_key}")
print(f"client_public_key: {client_public_key}")

# Send client public key
sock.sendall(point_to_bytes(client_public_key))


print()
print("Sent client_public_key to server.")
print()

# Receive server public key
server_data = sock.recv(1024)  # adjust buffer size if needed
server_public_key = bytes_to_point(server_data)

print("Received server_public_key.")
print(f"server_public_key : {server_public_key}")
print()

client_shared_point = elliptic_curves.point_exponent(CURVE_PARAMETERS, server_public_key, client_private_key)

print("Shared elliptic curve co-ordinates established.")
print(f"Shared_point : {client_shared_point}")
print()

aes_key = derive_aes_key(client_shared_point[0])

print(f"Derived aes key : {aes_key}")
print()

# -----------------------------------------------------------------------------


server_ip, server_port = sock.getpeername()
print(f"Connected to server at {server_ip}:{server_port}")
print("Send QUIT to terminate the connection.")
print()


while True:

    client_message = input("You: ")
    encoded_client_message = client_message.encode()

    num_used_once = os.urandom(12)
    ciphertext, tag = aes.encrypt(encoded_client_message, aes_key, num_used_once)

    message_format.send_packet(sock, num_used_once, tag, ciphertext)

    packet = message_format.recv_packet(sock)
    if packet is None:
        break

    nonce, tag, ciphertext = packet
    plaintext = aes.decrypt(ciphertext, tag, aes_key, nonce)

    server_message = plaintext.decode().rstrip('\n')
    print(f"Server: {server_message}")


sock.close()
print("Thankyou for using cryptographically secure services, have a nice day!")
