import socket
import struct
import os
import stat
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from src.wireguard_tpm_security.netcomm import NetComm
from src.wireguard_tpm_security.tpm_security import TpmSigner, TpmSealer

from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import PUBLIC_KEY_PATH as WG_OWN_PUB_KEY_FILE_PATH, PSK_KEY_PATH as WG_PSK_FILE_PATH   # "/etc/wireguard/wg0.public, /etc/wireguard/wg0.psk "
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import TPM_WG_PSK_SEAL_NAME as WG_PSK_SEAL_NAME
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import TPM_WG_SEAL_KEY as WG_SEAL_KEY
from src.wireguard_tpm_security.auth_handshake.auth_handshake_common import TPM_SIGN_KEY_NAME as TPM_DEVICE_AUTH_KEY
from src.wireguard_tpm_security.auth_handshake.auth_handshake_common import PEER_PUB_KEY_FILE_NAME as PEER_AUTH_PUB_KEY_FILE_NAME
from src.wireguard_tpm_security.auth_handshake.auth_handshake_common import TPM_PEER_PUB_KEY_SEAL_NAME as TPM_PEER_AUTH_KEY_SEAL


TPM_WG_PEER_PUB_KEY_SEAL_NAME = "wg_pub_peer_seal"

HEADER_FORMAT = "!HH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

WG_PEER_PUB_KEY_FILE_PATH = "/etc/wireguard/wg0_peer.public"

PEER_AUTH_PUB_KEY_FILE_PATH = os.path.join("/home/raul/Desktop/Wireguard-TPM-security/src/wireguard_tpm_security/auth_handshake", PEER_AUTH_PUB_KEY_FILE_NAME)


def pack(data : bytes, signature : bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, len(data), len(signature))

    payload_fmt = f"!{len(data)}s{len(signature)}s"
    payload = struct.pack(payload_fmt, data, signature)

    return (header + payload)


def unpack(data : bytes) -> tuple[bytes, bytes]:
    data_size, signature_size = struct.unpack_from(HEADER_FORMAT, data)

    payload_fmt = f"!{data_size}s{signature_size}s"
    data, signature = struct.unpack_from(payload_fmt, data, HEADER_SIZE)

    return (data, signature)


def read_file(path : str, read_mode="rb"):
    file = open(path, read_mode)
    return file.read().strip()


def verify_RSA_signature(RSA_key : bytes | str, data : bytes, signature : bytes) -> bool:
    verifier = pss.new(RSA.import_key(RSA_key))     # Setup signature verifier
    hash = SHA256.new(data)                         # Compute hash for given data
    try:
        # Check if signature is valid
        verifier.verify(hash, signature)   # type: ignore
        return True
    except ValueError:
        return False
    

def write_secure_file(path : str, data : bytes):
    # Create file with mode 0600
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            if not data.endswith(b"\n"):
                f.write(b"\n")
    finally:
        # Ensure permissions remain 0600
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def wg_public_key_exchange(conn_socket : socket.socket, *, is_client : bool):
    communicator = NetComm(conn_socket)
    tpm_signer = TpmSigner(TPM_DEVICE_AUTH_KEY)

    wg_own_pub_key = read_file(WG_OWN_PUB_KEY_FILE_PATH)
    wg_own_pub_key_signature, _, _ = tpm_signer.sign_data(wg_own_pub_key)

    wg_peer_pub_key : bytes
    wg_psk : bytes

    file_peer_auth_pub_key = read_file(PEER_AUTH_PUB_KEY_FILE_PATH)
    
    if is_client is True:
        # Send wg_own_pub_key to peer
        communicator.send(pack(wg_own_pub_key, wg_own_pub_key_signature))
        print("Sent wg_own_pub_key & signature!")

        # Then receive wg_peer_pub_key from peer, together with signature
        wg_peer_pub_key, wg_peer_pub_signature = unpack(communicator.receive())
        print("Recieved wg_peer_pub_key & signature!")

        # Then receive wg_psk from peer, together with signature
        wg_psk, wg_psk_signature = unpack(communicator.receive())
        print("Recieved wg_psk & signature!")

        # Check if local peer_auth_pub_key is authentic (with TPM), to make sure the other device is the known, authorized one
        if TpmSealer(TPM_PEER_AUTH_KEY_SEAL).verify_with_seal(file_peer_auth_pub_key) is False:
            print("*** peer_auth_pub_key is NOT the one linked to the TPM! ***")
            return
        print("peer_auth_pub_key verified locally with the TPM!")

        # Check if received signature for wg_peer_pub_key is valid
        if verify_RSA_signature(file_peer_auth_pub_key, wg_peer_pub_key, wg_peer_pub_signature) is False:
            print("*** wg_peer_pub_key signature INVALID! ***")
            return
        print("wg_peer_pub_key was authentically signed!")

        # Check if received signature for wg_psk is valid
        if verify_RSA_signature(file_peer_auth_pub_key, wg_psk, wg_psk_signature) is False:
            print("*** wg_psk signature INVALID! ***")
            return
        print("wg_psk was authentically signed!")

        if TpmSealer(WG_PSK_SEAL_NAME, WG_SEAL_KEY).link_with_seal(wg_psk, system_seal=True) is True:
            write_secure_file(WG_PSK_FILE_PATH, wg_psk)
            print("Peer provided PSK hash sealed inside TPM!")
        else:
            print("*** Peer WG interface was NOT associated! ***")
            return

    else:
        # Receive wg_peer_pub_key from peer, together with signature
        wg_peer_pub_key, wg_peer_pub_signature = unpack(communicator.receive())
        print("Recieved wg_peer_pub_key & signature!")

        # Check if local peer_auth_pub_key is authentic (with TPM), to make sure the other device is the known one
        if TpmSealer(TPM_PEER_AUTH_KEY_SEAL).verify_with_seal(file_peer_auth_pub_key) is False:
            print("*** peer_auth_pub_key is NOT the one linked to the TPM! ***")
            return
        print("peer_auth_pub_key verified locally with the TPM!")

        # Check if received signature for wg_peer_pub_key is valid
        if verify_RSA_signature(file_peer_auth_pub_key, wg_peer_pub_key, wg_peer_pub_signature) is False:
            print("*** wg_peer_pub_key_hash signature INVALID! ***")
            return
        print("wg_peer_pub_key_hash was authentically signed!")

        # Then send wg_own_pub_key to peer
        communicator.send(pack(wg_own_pub_key, wg_own_pub_key_signature))
        print("Sent wg_own_pub_key & signature!")

        # Then send wg_psk to peer
        wg_psk = read_file(WG_PSK_FILE_PATH)
        wg_psk_signature, _, _ = tpm_signer.sign_data(wg_psk)
        communicator.send(pack(wg_psk, wg_psk_signature))
        print("Sent wg_psk & signature!")
    
    if TpmSealer(TPM_WG_PEER_PUB_KEY_SEAL_NAME, WG_SEAL_KEY).link_with_seal(wg_peer_pub_key, system_seal=True) is True:    # Seal peer_public_key hash in TPM
        # Write peer_public_key to disk
        write_secure_file(WG_PEER_PUB_KEY_FILE_PATH, wg_peer_pub_key)
        print("Peer public WG key hash sealed inside TPM!")
        print("<<< Peer device WG interface is now asociated with this device! >>>")
    else:
        print("*** Peer WG interface was NOT associated! ***")
