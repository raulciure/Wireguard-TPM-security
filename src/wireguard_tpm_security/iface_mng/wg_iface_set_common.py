import os
import stat
import tempfile
import subprocess
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import TPM_WG_SEAL_KEY, TPM_WG_PRIVATE_SEAL_NAME, TPM_WG_PSK_SEAL_NAME
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, PSK_KEY_PATH
from src.wireguard_tpm_security.tpm_security import TpmSealer

# TPM path/name
TPM_WG_KEYS_SEAL_PATH = TPM_WG_SEAL_KEY
TPM_WG_PRIV_KEY_SEAL_NAME = TPM_WG_PRIVATE_SEAL_NAME
TPM_WG_PSK_SEAL_NAME = TPM_WG_PSK_SEAL_NAME

# WG key files paths
WG_PRIV_KEY_FILE_PATH = PRIVATE_KEY_PATH        # "/etc/wireguard/wg0.private"
WG_PUB_KEY_FILE_PATH = PUBLIC_KEY_PATH          # "/etc/wireguard/wg0.public"
WG_PSK_FILE_PATH = PSK_KEY_PATH                 # "/etc/wireguard/wg0.psk"


def run(cmd, *, input_bytes=None, check=True):
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        input=input_bytes,
        capture_output=True,
        check=check,
    )


def unseal_and_verify(tpm_obj_name : str, tpm_obj_path : str, file_name : str) -> bytes:
    unsealer = TpmSealer(tpm_obj_name, tpm_obj_path)

    key_file = open(file_name, "rb")
    key = key_file.read().strip()
    key_file.close()

    if unsealer.verify_with_seal(key) is False:
        raise ValueError(f"*** {tpm_obj_name} (from file) hash differs from TPM sealed hash! ***")
    
    return key


def write_secret_tempfile(secret_bytes : bytes):
    fd, path = tempfile.mkstemp(prefix="wgkey-", dir="/run")
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        with os.fdopen(fd, "wb") as f:
            f.write(secret_bytes)
            f.write(b"\n")
        return path
    except Exception:
        os.close(fd)
        raise


def ensure_interface_exists(iface):
    # Create only if it doesn't already exist
    result = subprocess.run(
        ["ip", "link", "show", "dev", iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        run(["ip", "link", "add", "dev", iface, "type", "wireguard"])


def address_exists(iface, cidr):
    result = subprocess.run(
        ["ip", "-brief", "address", "show", "dev", iface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return cidr in result.stdout