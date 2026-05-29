from __future__ import annotations

import asyncio
import fcntl
import os
import random
import socket
import struct
import subprocess
import time as time_module
from typing import Optional

from netghost.models.packet import PacketInfo, Layer2Info, Layer3Info, Layer4Info


def _detect_default_interface() -> str:
    env_iface = os.environ.get("INTERFACE", "")
    if env_iface:
        return env_iface
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except (FileNotFoundError, subprocess.TimeoutExpired, IndexError):
        pass
    return "eth0"


class CaptureEngine:
    def __init__(self, interface: str = "") -> None:
        self.interface = interface or _detect_default_interface()
        self._sniffer = None
        self._running = False
        self._test_mode = False
        self._test_task: Optional[asyncio.Task] = None
        self._queue: asyncio.Queue[PacketInfo] = asyncio.Queue(maxsize=5000)

    @property
    def queue(self) -> asyncio.Queue[PacketInfo]:
        return self._queue

    @property
    def is_test_mode(self) -> bool:
        return self._test_mode

    async def start(self, interface: Optional[str] = None, force_test: bool = False) -> None:
        if self._running:
            return
        if interface:
            self.interface = interface

        if force_test:
            self._test_mode = True
            self._running = True
            self._test_task = asyncio.create_task(self._generate_test_packets())
            return

        try:
            from scapy.all import AsyncSniffer  # type: ignore
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=lambda pkt: self._handler(pkt),
                store=False,
            )
            self._sniffer.start()
            self._running = True
        except (PermissionError, OSError, ImportError):
            self._test_mode = True
            self._running = True
            self._test_task = asyncio.create_task(self._generate_test_packets())

    def _handler(self, pkt) -> None:
        from netghost.models.packet import PacketInfo as PI
        info = PI.from_scapy(pkt)
        if info is not None:
            try:
                self._queue.put_nowait(info)
            except asyncio.QueueFull:
                try:
                    self._queue.get_nowait()
                    self._queue.put_nowait(info)
                except asyncio.QueueEmpty:
                    pass

    async def _generate_test_packets(self) -> None:
        test_ips = [
            ("192.168.1.1", "192.168.1.100", 443, 54321, "HTTPS", "TCP"),
            ("10.0.0.5", "8.8.8.8", 53, 12345, "DNS", "UDP"),
            ("172.16.0.10", "192.168.1.1", 80, 45678, "HTTP", "TCP"),
            ("192.168.1.100", "203.0.113.5", 22, 22, "SSH", "TCP"),
            ("8.8.8.8", "192.168.1.100", 53, 53, "DNS", "UDP"),
            ("192.168.1.1", "224.0.0.251", 5353, 5353, "mDNS", "UDP"),
            ("10.0.0.5", "239.255.255.250", 1900, 1900, "SSDP", "UDP"),
            ("192.168.1.100", "1.1.1.1", 443, 38001, "HTTPS", "TCP"),
        ]
        macs = [
            "00:1a:2b:3c:4d:5e", "aa:bb:cc:dd:ee:ff",
            "10:20:30:40:50:60", "de:ad:be:ef:00:01",
        ]

        while self._running:
            src_ip, dst_ip, sp, dp, app, proto = random.choice(test_ips)
            src_mac = random.choice(macs)
            dst_mac = random.choice(macs)
            size = random.randint(64, 1500)
            flags = random.choice([["SYN"], ["SYN", "ACK"], ["ACK"], ["FIN", "ACK"], ["PSH", "ACK"]])

            pkt = PacketInfo(
                timestamp=time_module.time(),
                size=size,
                summary=f"{proto} {src_ip}:{sp} > {dst_ip}:{dp}",
                raw_hex="00" * min(size, 64),
                l2=Layer2Info(src_mac=src_mac, dst_mac=dst_mac, ether_type=0x0800),
                l3=Layer3Info(src_ip=src_ip, dst_ip=dst_ip, proto=6 if proto == "TCP" else 17, ttl=random.randint(32, 128), version=4),
                l4=Layer4Info(src_port=sp, dst_port=dp, protocol=proto, flags=flags, window=65535),
                app_protocol=app,
                app_details={"request": f"{proto} {src_ip}:{sp} → {dst_ip}:{dp}"},
            )

            try:
                self._queue.put_nowait(pkt)
            except asyncio.QueueFull:
                try:
                    self._queue.get_nowait()
                    self._queue.put_nowait(pkt)
                except asyncio.QueueEmpty:
                    pass

            await asyncio.sleep(random.uniform(0.3, 2.0))

    def stop(self) -> None:
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._test_task:
            self._test_task.cancel()
            self._test_task = None

    @property
    def running(self) -> bool:
        return self._running

    @staticmethod
    def list_interfaces() -> list[str]:
        try:
            from scapy.all import conf  # type: ignore
            return sorted(conf.ifaces.data.keys())
        except Exception:
            return ["eth0", "wlan0", "lo"]

    def get_interface_info(self) -> tuple[str, str]:
        iface = self.interface
        ip = self._get_ip(iface)
        mac = self._get_mac(iface)
        return ip, mac

    @staticmethod
    def _get_ip(iface: str) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(), 0xc0206921,
                struct.pack("256s", iface[:15].encode())
            )[20:24])
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    @staticmethod
    def _get_mac(iface: str) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            mac_bytes = fcntl.ioctl(
                s.fileno(), 0x8927,
                struct.pack("256s", iface[:15].encode())
            )[18:24]
            s.close()
            return ":".join(f"{b:02x}" for b in mac_bytes)
        except Exception:
            return "00:00:00:00:00:00"
