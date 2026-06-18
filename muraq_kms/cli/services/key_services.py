
import time
import sys
from argparse import Namespace
from typing import Callable, Optional

from muraq_kms.cli.ui.ui import UI
from muraq_kms.cli.ui.widgets import Spinner

from muraq_kms.policies.models import KeyAccessPolicy

from muraq_kms.keys.manager import KeyManager

from muraq_kms.cli.args.key_args import KeyCreateArgs

from muraq_kms.crypto.registry import MuraqKMSAlgorithms

def handle_create(key_manager:KeyManager, actor:str, parsed_args:Namespace) -> None:
    args_dict = vars(parsed_args).copy()
    args_dict.pop("operation", None)

    try:
        spec = MuraqKMSAlgorithms.get_spec(args_dict["algorithm_name"])
        args_dict["algorithm_type"] = spec.type.value
    except ValueError as algo_err:
        print(f"{UI.STATUS.FAIL} Cryptographic Constraint Violation: {str(algo_err)}")
        return

    args_dict['actor'] = actor

    try:
        args = KeyCreateArgs(**args_dict)
    except Exception as validation_err:
        print(f"{UI.STATUS.FAIL} Argument Validation Error: {str(validation_err)}")
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