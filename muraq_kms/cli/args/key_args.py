import argparse
from typing import Optional
from pydantic import BaseModel, Field

def build_key_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="key", add_help=False, exit_on_error=False, prefix_chars='+')
    subparsers = parser.add_subparsers(dest="operation", required=True)

    p_create = subparsers.add_parser("-create", add_help=False, exit_on_error=False)
    p_create.add_argument("name")
    p_create.add_argument("algorithm")
    p_create.add_argument("--purpose", required=True, type=str.lower, choices=["encryption", "signing", "wrapping"])
    p_create.add_argument("--desc", nargs="?", default=None)
    p_create.add_argument("--export", action="store_true")
    p_create.add_argument("--borrow", action="store_true")
    p_create.add_argument("--ttl", type=int, default=None)

    p_view = subparsers.add_parser("-v", add_help=False, exit_on_error=False)
    p_view.add_argument("-name", required=True)

    p_borrow = subparsers.add_parser("-b", add_help=False, exit_on_error=False)
    p_borrow.add_argument("name")
    p_borrow.add_argument("version", type=int, nargs="?", default=None)

    p_list = subparsers.add_parser("-ls", add_help=False, exit_on_error=False)
    p_list.add_argument("-l", type=int, default=10, dest="limit")

    p_export = subparsers.add_parser("-export", add_help=False, exit_on_error=False)
    p_export.add_argument("name")
    p_export.add_argument("-v", "--version", type=int, nargs="?", default=None)
    p_export.add_argument("-f", "--format", type=str, default="json", help="Output format: json, env, txt, or env:CUSTOM_VAR_NAME")
    p_export.add_argument("-o", "--output", type=str, default=None, help="Destination path to file or directory directory.")

    return parser

class KeyCreateArgs(BaseModel):
    export:bool = Field(False)
    borrow:bool = Field(False)
    ttl:int = Field(0)
    algorithm_name:str = Field(...)
    algorithm_type:str = Field(...)
    actor:str = Field(...)
    key_name:str = Field(...)
    purpose:str = Field(...)
    description:Optional[str] = Field(None)
