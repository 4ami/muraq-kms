from socket import gethostname
from getpass import getuser
import os
import uuid

def hardware_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    content = f.read().strip()
                    if content: return content[:12]
            except Exception:
                pass
    
    mac_add = uuid.getnode()
    if (mac_add >> 40) & 1 == 0:
        return f"mac-{hex(mac_add)[2:][:12]}"
    return "unknown-host-id"

def getinfo() -> str:
    user = getuser()
    host = gethostname()
    id = hardware_id()
    return f"{user}:{host}-{id}"

def cli_actor() -> str:
    info = getinfo()
    return f"cli:{info}"

def sdk_actor() -> str:
    info = getinfo()
    return f"sdk:{info}"