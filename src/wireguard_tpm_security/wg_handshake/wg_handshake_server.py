import socket
# import src.wireguard_tpm_security.utils as utils
from src.wireguard_tpm_security.wg_handshake.wg_handshake_common import wg_public_key_exchange


def wg_handshake_server():
    # host_ip = utils.get_host_ip()
    # host_ip = '127.0.0.1'
    host_ip = '192.168.81.81'
    host_port = 4020

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host_ip, host_port))
    server_socket.listen(10)

    print("[*] Waiting for client connection...")

    client_socket, client_address = server_socket.accept()
    print(f"[*] Accepted connection from client: {client_address}")

    wg_public_key_exchange(client_socket, is_client=False)   # Call key exchange routine

    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    wg_handshake_server()