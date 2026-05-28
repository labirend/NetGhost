from __future__ import annotations

from typing import Optional

from textual.widgets import Static, TabbedContent, TabPane
from textual.widget import Widget
from rich.text import Text
from rich.style import Style

from netghost.models.packet import PacketInfo
from netghost.i18n import t


class DetailPanel(Widget):
    """Bottom detail panel showing layered packet info."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._current_packet: Optional[PacketInfo] = None

    def compose(self):
        yield Static(t("detail.no_selection"), id="detail-content")

    def show_packet(self, pkt: PacketInfo) -> None:
        """Display details for a given packet."""
        self._current_packet = pkt
        content = self._build_detail_text(pkt)
        detail_widget = self.query_one("#detail-content", Static)
        detail_widget.update(content)

    def _build_detail_text(self, pkt: PacketInfo) -> Text:
        result = Text()

        # Layer 2
        if pkt.l2:
            result.append(f"⚡ {t('detail.l2')}\n", Style(color="#ff69b4", bold=True))
            result.append(f"  {pkt.l2.src_mac}  →  {pkt.l2.dst_mac}")
            result.append(f"  (0x{pkt.l2.ether_type:04x})\n", Style(color="#808080"))

        # Layer 3
        if pkt.l3:
            result.append(f"\n🌐 {t('detail.l3')}\n", Style(color="#00ffff", bold=True))
            ip_ver = f"IPv{pkt.l3.version}"
            result.append(f"  {ip_ver}  {pkt.l3.src_ip}  →  {pkt.l3.dst_ip}")
            result.append(f"  TTL={pkt.l3.ttl}  Proto={pkt.l3.proto}\n", Style(color="#808080"))

        # Layer 4
        if pkt.l4:
            result.append(f"\n🔌 {t('detail.l4')}\n", Style(color="#00ff41", bold=True))
            result.append(f"  {pkt.l4.protocol}  {pkt.l4.src_port}  →  {pkt.l4.dst_port}")
            if pkt.l4.flags:
                result.append(f"  Flags: {', '.join(pkt.l4.flags)}")
            result.append(f"  Window={pkt.l4.window}\n", Style(color="#808080"))

        # Application
        if pkt.app_protocol:
            result.append(f"\n📦 {pkt.app_protocol}\n", Style(color="#ff8c00", bold=True))
            if pkt.app_details:
                for key, val in pkt.app_details.items():
                    if isinstance(val, list):
                        val_str = ", ".join(str(v) for v in val[:3])
                    else:
                        val_str = str(val)
                    result.append(f"  {key}: {val_str}\n", Style(color="#c0c0c0"))

        # Payload hex (first 64 bytes)
        if pkt.raw_hex:
            result.append(f"\n📄 {t('detail.payload')}\n", Style(color="#bf00ff", bold=True))
            raw = bytes.fromhex(pkt.raw_hex)
            hex_lines = self._hexdump(raw[:64])
            for line in hex_lines:
                result.append(f"  {line}\n", Style(color="#808080"))

        return result

    @staticmethod
    def _hexdump(data: bytes) -> list[str]:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
        return lines

    def clear(self) -> None:
        detail_widget = self.query_one("#detail-content", Static)
        detail_widget.update(t("detail.no_selection"))
