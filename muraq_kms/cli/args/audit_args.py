import argparse

def build_audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit", add_help=False, exit_on_error=False, prefix_chars="+")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    p_list = subparsers.add_parser("-ls", add_help=False, exit_on_error=False)
    p_list.add_argument("-l", type=int, default=10, dest="limit")

    p_check = subparsers.add_parser("-check", add_help=False, exit_on_error=False)
    p_check.add_argument("-v", action="store_true", dest="verbose")

    return parser