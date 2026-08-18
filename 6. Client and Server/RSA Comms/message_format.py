import struct


def send_packet(sock, nonce, tag, ciphertext):
    payload = nonce + tag + ciphertext
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_packet(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None

    length = struct.unpack("!I", raw_len)[0]

    data = b""
    while len(data) < length:
        data += sock.recv(length - len(data))

    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    return nonce, tag, ciphertext