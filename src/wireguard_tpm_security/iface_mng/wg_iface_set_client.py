import os
from src.wireguard_tpm_security.wg_handshake.wg_handshake_common import TPM_WG_PEER_PUB_KEY_SEAL_NAME, WG_PEER_PUB_KEY_FILE_PATH
from src.wireguard_tpm_security.iface_mng.wg_iface_set_common import *


# --- Config constants ---
# Interface config
IFACE = "wg0"
ADDRESS = "10.0.0.2/24"

# Peer config
PEER_ALLOWED_IPS = "10.0.0.1/32, 192.168.81.0/24"
PEER_ENDPOINT = "192.168.81.81:51820"
# PEER_KEEPALIVE = "25"                     # omit or set None if not needed

PEER_SUBNET = "192.168.81.0/24"

def main():
    priv_tmp = None
    psk_tmp = None

    try:
        # Unseal secrets from TPM
        private_key = unseal_and_verify(TPM_WG_PRIV_KEY_SEAL_NAME, TPM_WG_KEYS_SEAL_PATH, WG_PRIV_KEY_FILE_PATH)
        psk = unseal_and_verify(TPM_WG_PSK_SEAL_NAME, TPM_WG_KEYS_SEAL_PATH, WG_PSK_FILE_PATH)
        peer_pub_key = unseal_and_verify(TPM_WG_PEER_PUB_KEY_SEAL_NAME, TPM_WG_KEYS_SEAL_PATH, WG_PEER_PUB_KEY_FILE_PATH)

        # Write them to secure temp files for wg set
        priv_tmp = write_secret_tempfile(private_key)
        psk_tmp = write_secret_tempfile(psk)

        # Create interface if needed
        ensure_interface_exists(IFACE)

        # Configure WireGuard interface itself
        wg_cmd = [
            "wg", "set", IFACE,
            "private-key", priv_tmp,
            "peer", peer_pub_key.decode(),
            "endpoint", PEER_ENDPOINT,
            "allowed-ips", PEER_ALLOWED_IPS,
            "preshared-key", psk_tmp
        ]

        # Run wg console command
        run(wg_cmd)

        # Add IP address (only if not already present)
        if not address_exists(IFACE, ADDRESS):
            run(["ip", "address", "add", ADDRESS, "dev", IFACE])

        # Add routes for WG tunnel
        add_route_cmd = [
            "ip", "route", "add",
            PEER_SUBNET, "dev", IFACE
        ]
        run(add_route_cmd)

        # Bring interface up
        run(["ip", "link", "set", "up", "dev", IFACE])

        print(f"{IFACE} configured and up")
    finally:
        # Delete temp files
        for p in (priv_tmp, psk_tmp):
            if p:
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    main()