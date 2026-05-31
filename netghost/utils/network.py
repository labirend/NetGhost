from __future__ import annotations

from typing import Optional


def get_default_interface() -> str:
    env_iface = __import__("os").environ.get("INTERFACE", "").strip()
    if env_iface:
        return env_iface
    try:
        from scapy.all import conf as scapy_conf
        iface = scapy_conf.iface
        if iface and iface.name and iface.name != "lo":
            return iface.name
    except Exception:
        pass
    try:
        from scapy.all import conf as scapy_conf
        ifaces = sorted(scapy_conf.ifaces.data.keys())
        if ifaces:
            return ifaces[0]
    except Exception:
        pass
    return "eth0"


def get_interface_ip(iface: str) -> Optional[str]:
    try:
        from scapy.all import conf as scapy_conf
        ip = scapy_conf.ifaces[iface].ip
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    return None


def get_interface_mac(iface: str) -> Optional[str]:
    try:
        from scapy.all import conf as scapy_conf
        mac = scapy_conf.ifaces[iface].mac
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    return None
