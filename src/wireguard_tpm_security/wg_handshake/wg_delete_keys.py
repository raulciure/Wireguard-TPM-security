import os
from src.wireguard_tpm_security.tpm_security import get_obj_tpm_path, delete_obj
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, PSK_KEY_PATH
from src.wireguard_tpm_security.wg_handshake.wg_gen_keys import TPM_WG_SEAL_KEY, TPM_WG_PRIVATE_SEAL_NAME, TPM_WG_PSK_SEAL_NAME


def wg_delete_keys():
    try:
        # Delete PSK seal
        delete_obj(get_obj_tpm_path(TPM_WG_PSK_SEAL_NAME))
        print("PSK seal deleted!")
    except:
        print("PSK could NOT be deleted!")

    try:
        # Delete Priv key seal
        delete_obj(get_obj_tpm_path(TPM_WG_PRIVATE_SEAL_NAME))
        print("Private key seal deleted!")
    except:
        print("Private key seal could NOT be deleted!")
        
    try:
        # Delete wrapper key
        delete_obj(get_obj_tpm_path(TPM_WG_SEAL_KEY))
        print("WG wrapper key deleted!")
    except:
        print("WG wrapper key could NOT be deleted!")


    # Delete priv key file
    os.remove(PRIVATE_KEY_PATH)
    print("Private key file deleted!")
    # Delete pub key file
    os.remove(PUBLIC_KEY_PATH)
    print("Public key file deleted!")
    # Delete psk file
    try:
        os.remove(PSK_KEY_PATH)
        print("PSK file deleted!")
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    wg_delete_keys()