
import json
from pathlib import Path
import time
import sys
from argparse import Namespace
from typing import Any, Callable, Optional

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Spinner, Frame

from muraq_kms.crypto.primitives import mask
from muraq_kms.policies.models import KeyAccessPolicy

from muraq_kms.keys.manager import KeyManager

from muraq_kms.cli.args.key_args import KeyCreateArgs

from muraq_kms.crypto.registry import MuraqKMSAlgorithms

def handle_create(key_manager:KeyManager, actor:str, parsed_args:Namespace) -> None:
    args_dict = vars(parsed_args).copy()
    args_dict.pop("operation", None)

    try:
        spec = MuraqKMSAlgorithms.get_spec(args_dict["algorithm"])
        args_dict["algorithm_name"] = args_dict.pop("algorithm")
        args_dict["algorithm_type"] = spec.type.value
    except ValueError as algo_err:
        print(f"{UI.STATUS.FAIL} Cryptographic Constraint Violation: {str(algo_err)}")
        return

    args_dict['actor'] = actor
    args_dict['key_name'] = args_dict.pop('name')
    try:
        args = KeyCreateArgs(**args_dict)
    except Exception:
        print(f"{UI.STATUS.FAIL} Argument Validation Error")
        return
        
    try:
        policy = KeyAccessPolicy(
            export=args.export,
            borrow=args.borrow,
            borrow_ttl_seconds=args.ttl
        )
    except Exception as policy_error:
        print(f"{UI.STATUS.FAIL} Policy Validation Error: {str(policy_error).splitlines()[0]}")
        return

    try:
        with Spinner(f"Generating cryptographically sound {args.algorithm_name} material primitives for '{args.key_name}'..."):
                model = key_manager.create_key_sync(
                actor=args.actor, 
                name=args.key_name, 
                purpose=args.purpose, 
                algorithm=args.algorithm_name,
                description=args.description,
                policy=policy
            )
        print(f"{UI.STATUS.SUCCESS} Key version tracking container '{model.kid}' successfully generated.")

        print(f"   {UI.ANSIESCAPE.DIM}├─ Algorithm      : {args.algorithm_name} ({args.algorithm_type.upper()})")
        print(f"   ├─ Export Allowed : {policy.export}")
        print(f"   ├─ Borrow Scoped  : {policy.borrow}")
        print(f"   └─ Lease Window   : {policy.borrow_ttl_seconds}s{UI.ANSIESCAPE.RESET}\n")
    except Exception as e:
        print(f"{UI.STATUS.FAIL} Execution failed: {str(e)}")

def handle_borrow(key_manager:KeyManager, actor:str, key_name:str, flush_callback:Callable, key_version:Optional[str] = None):
    try:
        borrow_ctx = key_manager.borrow_key_sync(
            actor=actor,
            name=key_name,
            version=key_version
        )
        
        print(f"{UI.STATUS.INFO} Requesting secure execution lease allocation segment...")
        
        with borrow_ctx as lease:
            print(f"{UI.STATUS.SUCCESS} Ephemeral cryptographic lease successfully activated.")
            print(f"   {UI.ANSIESCAPE.DIM}├─ Lease Handle KeyID : {lease.key_id}")
            print(f"   ├─ Memory Address   : {hex(id(lease.key_material))}")
            print(f"   ├─ RAW KEY MATERIAL : {UI.COLORS.YELLOW}{lease.key_material.hex()}{UI.ANSIESCAPE.RESET}")
            print(f"   └─ Lifespan Window  : Active inside this terminal context{UI.ANSIESCAPE.RESET}")
            
            for remaining in range(lease.ttl_seconds, 0, -1):
                sys.stdout.write(f"\r⏳ [Lease Active] Time remaining: {remaining}s... ")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write('\r')
            flush_callback(None)
        print(f"{UI.STATUS.SUCCESS} Lease expired. Volatile transient memory registers zeroed out successfully.")
    except Exception as e:
        print(f"{UI.STATUS.FAIL} Lease Request Refused: {str(e)}")

def handle_list(key_manager:KeyManager, parsed_args:Namespace) -> None:
    limit = parsed_args.limit
    current_cursor = None
    page = 1

    while True:
        try:
            with Spinner(f"Retrieving cryptographic logical trace entries (Page {page})..."):
                rows, next_cursor, has_next = key_manager.list_keys_sync(
                    limit=limit,
                    cursor=current_cursor
                )
            
            if not rows and page == 1:
                print(f"{UI.STATUS.INFO} No logical security keys discovered inside this secure storage cluster vault.")
                return
            elif not rows:
                print(f"{UI.STATUS.INFO} Reached the end of the logical key register history.")
                return
            
            with Frame(title=f" MURAQ-KMS MANAGEMENT LOGICAL KEYS (Page {page}) ", color=UI.COLORS.CYAN) as frame:
                for row in rows:
                    header_line = f"Key: {UI.ANSIESCAPE.BOLD}{row['name']}{UI.ANSIESCAPE.RESET} | ID: {row['_id']}"
                    meta_line = f"   Purpose   : {UI.COLORS.YELLOW}{row['purpose']}{UI.ANSIESCAPE.RESET} | Algorithm: {UI.ANSIESCAPE.DIM}{row['algorithm']}{UI.ANSIESCAPE.RESET}"
                    version_line = f"   Active Ver: v{row['active_version']} | KID: {UI.ANSIESCAPE.DIM}{row['kid']}{UI.ANSIESCAPE.RESET}"
                    policy_line = f"   Policies  : Exportable={bool(row['exportable'])} | Borrowable={bool(row['borrowable'])} (TTL: {row['borrow_ttl_seconds']}s)"
                    
                    frame.line(header_line)
                    frame.line(meta_line)
                    frame.line(version_line)
                    frame.line(policy_line)
                    frame.line("—" * 65)
            
            if not has_next:
                break
            
            try:
                user_choice = input(f"\n{UI.STATUS.INFO} Press {UI.ANSIESCAPE.BOLD}[Enter]{UI.ANSIESCAPE.RESET} to view next page or type {UI.ANSIESCAPE.BOLD}[q]{UI.ANSIESCAPE.RESET} to exit: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            if user_choice in ["q", "quit", "exit"]:
                break
                
            current_cursor = next_cursor
            page += 1
        
        except Exception as e:
            print(f"{UI.STATUS.FAIL} Execution trace pagination aborted: {str(e)}")
            return

def handle_version(key_manager:KeyManager, name:str) -> None:
    try:
        with Spinner(f"Querying active cryptographic container descriptor for '{name}'..."):
            model = key_manager.get_key_version_sync(name=name)
        if not model:
            print(f"{UI.STATUS.FAIL} Key Reference Error: No active cryptographic key variant found named '{name}'.")
            return
        
        model.raw_material = mask(model.raw_material)
        dt_str = model.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        status_color = UI.COLORS.GREEN if model.state == "active" else UI.COLORS.YELLOW

        with Frame(title=f" CRYPTOGRAPHIC CONTAINER META: {name.upper()} ", color=UI.COLORS.CYAN) as frame:
            frame.line(f"Key Identifier (KID) : {UI.ANSIESCAPE.BOLD}{model.kid}{UI.ANSIESCAPE.RESET}")
            frame.line(f"Operational State    : {status_color}{model.state.upper()}{UI.ANSIESCAPE.RESET}")
            frame.line(f"Active Version Int   : v{model.version}")
            frame.line(f"Assigned Algorithm   : {model.algorithm}")
            frame.line(f"Generation Timestamp : {dt_str}")
            frame.line("—" * 65)
            frame.line(f"Encrypted Key Material Envelope (HEX Shorthand):")
            short_material = f"{model.raw_material[:32]}"
            frame.line(f"   {UI.ANSIESCAPE.DIM}{short_material}{UI.ANSIESCAPE.RESET}")
    except Exception as e:
        print(f"{UI.STATUS.FAIL} Operational Failure retrieving descriptor: {str(e)}")


def handle_export(key_manager:KeyManager, actor:str, parsed_args:Namespace) -> None:
    try:
        export_data = None
        with Spinner(f"Processing structural extraction payload for '{parsed_args.name}'..."):
            export_data = key_manager.export_sync(name=parsed_args.name, actor=actor, version=parsed_args.version)
        
        if not export_data:
            print(f"{UI.STATUS.FAIL} Operational Error: Extraction transaction could not be completed.")
            return
        
        key_hex = str(export_data['key_hex'])
        v_suffix = export_data['meta']['kid'].split(':')[-1] if ":" in export_data['meta']['kid'] else f"v{parsed_args.version or 1}"

        fmt_arg = parsed_args.format.lower().strip()
        fmt_type = "json"
        custom_env_var = f"{parsed_args.name}_{v_suffix}".upper()

        if fmt_arg.startswith("env"):
            fmt_type = "env"
            if ":" in fmt_arg:
                custom_env_var = parsed_args.format.split(":", 1)[1].strip()
        elif fmt_arg == "txt":
            fmt_type = "txt"
        
        out_arg = Path(parsed_args.output) if parsed_args.output else Path.cwd()

        if out_arg.is_dir():
            target_dir = out_arg
            if fmt_type == "env":
                target_file = target_dir / ".env"
            elif fmt_type == "txt":
                target_file = target_dir / f"{parsed_args.name}_{v_suffix}.txt"
            elif fmt_type == "json":
                target_file = target_dir / f"{parsed_args.name}_{v_suffix}.json"
            else:
                print(f"{UI.STATUS.FAIL} Unsupported format")
                return
        else:
            target_file = out_arg
        
        target_file.parent.mkdir(parents=True, exist_ok=True)

        if fmt_type == "env":
            _handle_env(target_file, custom_env_var, key_hex)
        elif fmt_type == "txt":
            if not _handle_txt(target_file, key_hex):
                return
        else:
            if not _handle_json(target_file, export_data):
                return

        print(f"{UI.STATUS.SUCCESS} Cryptographic extraction stream cleanly exported to resource disk.")
        print(f"   {UI.ANSIESCAPE.DIM}└─ Destination Path: {target_file}{UI.ANSIESCAPE.RESET}\n")   
    except Exception as e:
        print(f"{UI.STATUS.FAIL} Export transaction aborted: {str(e)}")


def _handle_env(file:Path, name:str, key:str) -> None:
    lines = []
    replaced = False

    if file.exists():
        with open(file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    
    for idx, line in enumerate(lines):
        if line.strip().startswith(f"{name}="):
            lines[idx] = f"{name}={key}\n"
            replaced = True
            break
    
    if not replaced:
        if lines and not lines[-1].endswith('\n'):
            lines.append('\n')
        lines.append(f"{name}={key}")
    
    with open(file, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def _handle_json(file:Path, data:dict[str, Any])-> bool:
    if file.exists():
        print(f"{UI.STATUS.WARN} Security package '{file.name}' already exists here.")
        return False
    
    with open(file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    
    return True

def _handle_txt(file:Path, key:str) -> bool:
    if file.exists():
        print(f"{UI.STATUS.WARN} Plaintext key container '{file.name}' already exists here.")
        return False
    with open(file, 'w', encoding='utf-8') as f:
        f.write(key)
    
    return True