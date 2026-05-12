import socket
from src.wireguard_tpm_security.wg_handshake.wg_handshake_common import wg_public_key_exchange


def wg_handshake_client():
    # dest_ip = '127.0.0.1'
    dest_ip = '192.168.81.81'
    dest_port = 4020

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((dest_ip, dest_port))
    print(f"[*] Established connection to server: {(dest_ip, dest_port)}")

    wg_public_key_exchange(server_socket, is_client=True)   # Call key exchange routine

    server_socket.close()


if __name__ == "__main__":
    wg_handshake_client()