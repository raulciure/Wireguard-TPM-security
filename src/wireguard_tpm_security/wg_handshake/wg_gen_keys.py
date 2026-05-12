import os
import stat
import subprocess
from src.wireguard_tpm_security.tpm_security import TpmSealer, create_key
from src.wireguard_tpm_security.parse_args import parse_args_wg_gen_key

PRIVATE_KEY_PATH = "/etc/wireguard/wg0.private"
PUBLIC_KEY_PATH = "/etc/wireguard/wg0.public"
PSK_KEY_PATH = "/etc/wireguard/wg0.psk"

TPM_WG_SEAL_KEY = "wg_seal_key/"
TPM_WG_PRIVATE_SEAL_NAME = "wg_priv_own_seal"
TPM_WG_PSK_SEAL_NAME = "wg_psk_seal"


def run(cmd, input_bytes=None):
    result = subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout


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


def main():
    # Handle cmdl args
    args = parse_args_wg_gen_key(__file__)

    # Generate private key using the official wg tool
    private_key = run(["wg", "genkey"]).strip()

    # Derive public key from the private key
    public_key = run(["wg", "pubkey"], input_bytes=private_key + b"\n").strip()

    # Create wrapper key for Wireguard keys
    create_key(TPM_WG_SEAL_KEY, key_type="decrypt,system,restricted,noda")

    if TpmSealer(TPM_WG_PRIVATE_SEAL_NAME, TPM_WG_SEAL_KEY).link_with_seal(private_key, system_seal=True) is False:
        print("*** WG private key seal error! ***")
        return
    print("<<< WG private key successfully sealed with the TPM! >>>")

    if args.is_server:
        # Generate PSK using the wg tool
        psk = run(["wg", "genpsk"]).strip()
    
        if TpmSealer(TPM_WG_PSK_SEAL_NAME, TPM_WG_SEAL_KEY).link_with_seal(psk, system_seal=True) is False:
            print("*** WG PSK seal error! ***")
            return
        print("<<< WG PSK successfully sealed with the TPM! >>>")

        # Save PSK on disk
        write_secure_file(PSK_KEY_PATH, psk)
        print(f"PSK written to:  {PSK_KEY_PATH}")
    
    # Save both keys on disk
    write_secure_file(PRIVATE_KEY_PATH, private_key)
    write_secure_file(PUBLIC_KEY_PATH, public_key)

    print(f"Private key written to: {PRIVATE_KEY_PATH}")
    print(f"Public key written to:  {PUBLIC_KEY_PATH}")
        

if __name__ == "__main__":
    main()