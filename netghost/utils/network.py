from __future__ import annotations

import subprocess
import re
from typing import Optional


def get_default_interface() -> str:
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "eth0"


def get_interface_ip(iface: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["ip", "addr", "show", iface],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r"inet\s+(\S+)", result.stdout)
        if match:
            return match.group(1).split("/")[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None
