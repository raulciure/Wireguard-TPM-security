import argparse
import os


def parse_args_wg_gen_key(prog_path : str):
    parser = argparse.ArgumentParser(os.path.basename(prog_path))

    parser.add_argument("--is-server", action="store_true", help="Generate keys as for the server device (include PSK)")

    args = parser.parse_args()

    return args