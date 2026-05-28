from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from netghost.models.packet import PacketInfo


class PcapRecorder:
    def __init__(self, output_dir: str = "") -> None:
        self._recording = False
        self._packets: list[PacketInfo] = []
        self._output_dir = output_dir or os.path.expanduser("~")
        self._filename: Optional[str] = None
        self._start_time: float = 0.0

    def start(self) -> str:
        self._packets.clear()
        self._recording = True
        self._start_time = time.time()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self._filename = f"netghost_{timestamp}.pcap"
        return self._filename

    def stop(self) -> Optional[str]:
        if not self._recording:
            return None
        self._recording = False
        filepath = self._save_pcap()
        self._filename = None
        return filepath

    def add_packet(self, pkt: PacketInfo) -> None:
        if self._recording:
            self._packets.append(pkt)

    def _save_pcap(self) -> Optional[str]:
        if not self._packets or not self._filename:
            return None
        try:
            from scapy.all import wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, Raw  # type: ignore
            scapy_packets = []
            for pkt_info in self._packets:
                scapy_pkt = self._build_scapy_packet(pkt_info)
                if scapy_pkt is not None:
                    scapy_packets.append(scapy_pkt)

            if scapy_packets:
                filepath = str(Path(self._output_dir) / self._filename)
                wrpcap(filepath, scapy_packets)
                return filepath
        except Exception:
            pass
        return None

    @staticmethod
    def _build_scapy_packet(info: PacketInfo):
        from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw
        pkt = Ether()

        if info.l3:
            ip_layer = IP(src=info.l3.src_ip, dst=info.l3.dst_ip, ttl=info.l3.ttl)
            if info.l4:
                if info.l4.protocol == "TCP":
                    ip_layer /= TCP(sport=info.l4.src_port, dport=info.l4.dst_port)
                elif info.l4.protocol == "UDP":
                    ip_layer /= UDP(sport=info.l4.src_port, dport=info.l4.dst_port)
                elif info.l4.protocol == "ICMP":
                    ip_layer /= ICMP()
            pkt = pkt / ip_layer

        if info.raw_hex:
            try:
                raw_bytes = bytes.fromhex(info.raw_hex)
                pkt = Ether(raw_bytes)
            except (ValueError, AttributeError):
                pass

        return pkt

    @property
    def recording(self) -> bool:
        return self._recording

    @property
    def elapsed(self) -> float:
        if self._recording:
            return time.time() - self._start_time
        return 0.0

    @property
    def packet_count(self) -> int:
        return len(self._packets)
