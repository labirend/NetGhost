from __future__ import annotations

from typing import Optional

from scapy.all import conf, send  # type: ignore
from scapy.layers.inet import IP, TCP  # type: ignore

from netghost.models.packet import PacketInfo


class Interceptor:
    """Handles connection blocking and RST injection."""

    def __init__(self, interface: str = "eth0") -> None:
        self.interface = interface
        self._blocked: set[str] = set()

    def send_rst(self, pkt: PacketInfo) -> bool:
        """Send RST packet to terminate a TCP connection."""
        if not pkt.l3 or not pkt.l4 or pkt.l4.protocol != "TCP":
            return False

        rst = IP(src=pkt.l3.dst_ip, dst=pkt.l3.src_ip) / TCP(
            sport=pkt.l4.dst_port,
            dport=pkt.l4.src_port,
            flags="R",
            seq=pkt.l4.ack,
        )
        try:
            send(rst, iface=self.interface, verbose=False)
            return True
        except Exception:
            return False

    def block_ip(self, ip: str) -> None:
        """Add IP to blocklist."""
        self._blocked.add(ip)

    def unblock_ip(self, ip: str) -> None:
        """Remove IP from blocklist."""
        self._blocked.discard(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    @property
    def blocked_ips(self) -> list[str]:
        return list(self._blocked)
