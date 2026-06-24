import argparse

def build_encrypt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="encrypt", add_help=False, exit_on_error=False)

    parser.add_argument("-k", "--key", required=True, help="Target logical key name identifier.")
    parser.add_argument(
        "--format", 
        type=str.lower, 
        choices=["base64", "hex", "raw"], 
        default=None,
        help="Output text serialization format (defaults: base64 for strings, raw for files)."
    )
    parser.add_argument("-o", "--output", type=str, default=None, help="Destination write filepath or directory.")

    src_group_enc = parser.add_mutually_exclusive_group(required=True)
    src_group_enc.add_argument("-m", "--message", type=str, help="Inline plaintext message string to encrypt.")
    src_group_enc.add_argument("-f", "--file", type=str, help="Filesystem location path of document to encrypt.")

    return parser