from __future__ import annotations

import time
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


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
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether, DNS, DHCP, Raw  # type: ignore
        except ImportError:
            return None

        raw_bytes = bytes(pkt)
        info = cls(
            timestamp=time.time(),
            size=len(raw_bytes),
            summary=pkt.summary() if hasattr(pkt, "summary") else "???",
            raw_hex=raw_bytes.hex(),
        )

        # Layer 2
        if Ether in pkt:
            ether = pkt[Ether]
            info.l2 = Layer2Info(
                src_mac=ether.src,
                dst_mac=ether.dst,
                ether_type=ether.type,
            )

        # Layer 3
        ip_layer = None
        if IP in pkt:
            ip_layer = pkt[IP]
            info.l3 = Layer3Info(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                proto=ip_layer.proto,
                ttl=ip_layer.ttl,
                version=4,
            )
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            info.l3 = Layer3Info(
                src_ip=ip6.src,
                dst_ip=ip6.dst,
                proto=ip6.nh,
                ttl=ip6.hlim,
                version=6,
            )

        # Layer 4
        if TCP in pkt:
            tcp = pkt[TCP]
            info.l4 = Layer4Info(
                src_port=tcp.sport,
                dst_port=tcp.dstport,
                protocol="TCP",
                flags=[f.name for f in tcp.flags if tcp.flags.value & f.value] if hasattr(tcp.flags, '__iter__') else [],
                window=tcp.window,
                seq=tcp.seq,
                ack=tcp.ack,
            )
            # Application layer detection
            info.app_protocol = _detect_app_protocol(info.l4.src_port, info.l4.dst_port)
            _parse_app_layer(pkt, info)
        elif UDP in pkt:
            udp = pkt[UDP]
            info.l4 = Layer4Info(
                src_port=udp.sport,
                dst_port=udp.dstport,
                protocol="UDP",
            )
            info.app_protocol = _detect_app_protocol(udp.sport, udp.dstport)
            _parse_app_layer(pkt, info)
        elif ICMP in pkt:
            info.l4 = Layer4Info(
                src_port=0,
                dst_port=0,
                protocol="ICMP",
            )
            info.app_protocol = "ICMP"

        # ARP
        if ARP in pkt:
            arp = pkt[ARP]
            info.app_protocol = "ARP"
            info.app_details = {
                "op": "request" if arp.op == 1 else "reply",
                "psrc": arp.psrc,
                "pdst": arp.pdst,
                "hwsrc": arp.hwsrc,
                "hwdst": arp.hwdst,
            }

        return info


def _detect_app_protocol(src_port: int, dst_port: int) -> str:
    port = dst_port if dst_port in (80, 443, 53, 22, 21, 25, 110, 143, 993, 3306, 5432, 6379, 8080, 8443, 67, 68, 123, 1900, 5353) else src_port

    services = {
        80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
        53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP",
        110: "POP3", 143: "IMAP", 993: "IMAPS",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        67: "DHCP", 68: "DHCP",
        123: "NTP",
        1900: "SSDP",
        5353: "mDNS",
    }
    return services.get(port, "")


def _parse_app_layer(pkt, info: PacketInfo) -> None:
    from scapy.all import DNS, DHCP, UDP, TCP, Raw  # type: ignore

    # DNS
    if DNS in pkt and UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
        dns = pkt[DNS]
        info.app_protocol = "DNS"
        queries = []
        if dns.qd:
            for q in dns.qd:
                try:
                    queries.append(q.qname.decode("utf-8", errors="replace").rstrip("."))
                except Exception:
                    queries.append("?")
        answers = []
        if dns.an:
            for a in dns.an:
                try:
                    answers.append(f"{a.rdata}" if hasattr(a, 'rdata') else "?")
                except Exception:
                    answers.append("?")
        info.app_details = {"queries": queries, "answers": answers}

    # DHCP
    if DHCP in pkt:
        info.app_protocol = "DHCP"
        dhcp = pkt[DHCP]
        opts = {}
        for opt in dhcp.options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[str(opt[0])] = str(opt[1])
        info.app_details = opts

    # HTTP (basic detection)
    if Raw in pkt:
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="replace")
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
                info.app_protocol = "HTTP"
                lines = payload.split("\r\n")[:5]
                info.app_details = {"request": lines[0] if lines else payload[:80]}
        except Exception:
            pass
