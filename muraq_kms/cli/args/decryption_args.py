import argparse

def build_decrypt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="decrypt", add_help=False, exit_on_error=False)

    parser.add_argument("-k", "--key", required=True, help="Target logical key name identifier.")
    parser.add_argument(
        "--format", 
        type=str.lower, 
        choices=["base64", "hex", "raw"], 
        default=None,
        help="Input interpretation format for handling string payloads."
    )
    parser.add_argument("-o", "--output", type=str, default=None, help="Destination plaintext extraction filepath.")

    src_group_dec = parser.add_mutually_exclusive_group(required=True)
    src_group_dec.add_argument("-m", "--message", type=str, help="Serialized ciphertext token payload string to decrypt.")
    src_group_dec.add_argument("-f", "--file", type=str, help="Filesystem location path of encrypted document.")

    return parser