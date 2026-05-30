from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import scapy.all
    _scapy_available = True
except ImportError:
    _scapy_available = False


@dataclass
class Layer2Info:
    src_mac: str
    dst_mac: str
    ether_type: int


@dataclass
class Layer3Info:
    src_ip: str
    dst_ip: str
    proto: int
    ttl: int
    version: int  # 4 or 6


@dataclass
class Layer4Info:
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP
    flags: list[str] = field(default_factory=list)
    window: int = 0
    seq: int = 0
    ack: int = 0


@dataclass
class PacketInfo:
    timestamp: float
    size: int
    summary: str
    raw_hex: str

    l2: Optional[Layer2Info] = None
    l3: Optional[Layer3Info] = None
    l4: Optional[Layer4Info] = None
    app_protocol: Optional[str] = None
    app_details: dict = field(default_factory=dict)

    _expanded: bool = False

    @property
    def expanded(self) -> bool:
        return self._expanded

    @expanded.setter
    def expanded(self, value: bool) -> None:
        self._expanded = value

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    @property
    def src_display(self) -> str:
        if self.l3:
            return self.l3.src_ip
        if self.l2:
            return self.l2.src_mac
        return "???"

    @property
    def dst_display(self) -> str:
        if self.l3:
            return self.l3.dst_ip
        if self.l2:
            return self.l2.dst_mac
        return "???"

    @property
    def port_info(self) -> str:
        if self.l4 and self.l4.protocol in ("TCP", "UDP"):
            return f"{self.l4.src_port} → {self.l4.dst_port}"
        return ""

    @property
    def proto_display(self) -> str:
        if self.app_protocol:
            return self.app_protocol
        if self.l4:
            return self.l4.protocol
        if self.l3:
            return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(self.l3.proto, f"IP({self.l3.proto})")
        return "???"

    @property
    def direction_icon(self) -> str:
        return "→" if not self.expanded else "▼"

    @classmethod
    def from_scapy(cls, pkt) -> Optional[PacketInfo]:
        global _scapy_available
        if not _scapy_available:
            return None

        raw = bytes(pkt)
        try:
            s = pkt.summary() if hasattr(pkt, "summary") else "???"
        except Exception:
            s = "???"

        info = cls(
            timestamp=time.time(),
            size=len(raw),
            summary=s,
            raw_hex=raw.hex(),
        )
        _fill_from_raw(info, raw)
        return info


def _mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


def _ipv4(b: bytes) -> str:
    return '.'.join(str(x) for x in b)


def _fill_from_raw(info: PacketInfo, raw: bytes) -> None:
    if len(raw) < 14:
        return

    eth_type = (raw[12] << 8) | raw[13]
    info.l2 = Layer2Info(
        src_mac=_mac(raw[6:12]),
        dst_mac=_mac(raw[0:6]),
        ether_type=eth_type,
    )

    # ARP
    if eth_type == 0x0806 and len(raw) >= 42:
        op = (raw[20] << 8) | raw[21]
        info.app_protocol = "ARP"
        info.app_details = {
            "op": "request" if op == 1 else "reply",
            "psrc": _ipv4(raw[28:32]),
            "pdst": _ipv4(raw[38:42]),
            "hwsrc": _mac(raw[22:28]),
            "hwdst": _mac(raw[32:38]),
        }
        return

    # IPv4
    if eth_type == 0x0800 and len(raw) >= 34:
        ihl = (raw[14] & 0x0F) * 4
        if ihl < 20 or len(raw) < 14 + ihl:
            return
        info.l3 = Layer3Info(
            src_ip=_ipv4(raw[26:30]),
            dst_ip=_ipv4(raw[30:34]),
            proto=raw[23],
            ttl=raw[22],
            version=4,
        )
        _parse_l4(info, raw, 14 + ihl, raw[23])
        return


def _parse_l4(info: PacketInfo, raw: bytes, offset: int, proto: int) -> None:
    if proto == 6 and len(raw) >= offset + 4:
        sport = (raw[offset] << 8) | raw[offset + 1]
        dport = (raw[offset + 2] << 8) | raw[offset + 3]
        info.l4 = Layer4Info(src_port=sport, dst_port=dport, protocol="TCP")
    elif proto == 17 and len(raw) >= offset + 4:
        sport = (raw[offset] << 8) | raw[offset + 1]
        dport = (raw[offset + 2] << 8) | raw[offset + 3]
        info.l4 = Layer4Info(src_port=sport, dst_port=dport, protocol="UDP")
    elif proto == 1:
        info.l4 = Layer4Info(src_port=0, dst_port=0, protocol="ICMP")

    if info.l4:
        info.app_protocol = _detect_app_protocol(info.l4.src_port, info.l4.dst_port)


def _detect_app_protocol(src_port: int, dst_port: int) -> str:
    port = dst_port if dst_port in {80, 443, 53, 22, 21, 25, 110, 143, 993, 3306, 5432, 6379, 8080, 8443, 67, 68, 123, 1900, 5353} else src_port
    services = {
        80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
        53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP",
        110: "POP3", 143: "IMAP", 993: "IMAPS",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        67: "DHCP", 68: "DHCP",
        123: "NTP", 1900: "SSDP", 5353: "mDNS",
    }
    return services.get(port, "")
