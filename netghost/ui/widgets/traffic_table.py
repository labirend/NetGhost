from __future__ import annotations

from collections import deque
from typing import Optional

from textual.widgets import DataTable
from textual.widget import Widget
from rich.text import Text
from rich.style import Style

from netghost.models.packet import PacketInfo
from netghost.i18n import t


class TrafficTable(Widget):

    MAX_ROWS = 500

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._packets: deque[PacketInfo] = deque(maxlen=self.MAX_ROWS)
        self._table: Optional[DataTable] = None
        self._filter = "ALL"
        self._dirty = False

    def compose(self):
        table = DataTable(id="traffic-table")
        table.add_columns(
            "",
            t("traffic.col.time"),
            t("traffic.col.src"),
            t("traffic.col.dst"),
            t("traffic.col.proto"),
            t("traffic.col.size"),
            t("traffic.col.info"),
        )
        table.cursor_type = "row"
        table.zebra_stripes = False
        table.show_cursor = True
        table.show_horizontal_scrollbar = True
        yield table

    def on_mount(self) -> None:
        self._table = self.query_one(DataTable)

    def get_table(self) -> Optional[DataTable]:
        return self._table

    def get_packet(self, row_index: int) -> Optional[PacketInfo]:
        try:
            return self._packets[row_index]
        except IndexError:
            return None

    def set_filter(self, filter_name: str) -> None:
        self._filter = filter_name
        self._rebuild()

    def add_packet(self, pkt: PacketInfo) -> None:
        self._packets.appendleft(pkt)
        if self._matches_filter(pkt):
            self._dirty = True
            self._rebuild()

    def _matches_filter(self, pkt: PacketInfo) -> bool:
        if self._filter == "ALL":
            return True
        return pkt.proto_display.upper() == self._filter

    def _rebuild(self) -> None:
        if not self._table:
            return
        self._table.clear()
        for i, pkt in enumerate(self._packets):
            if self._matches_filter(pkt):
                style = self._protocol_style(pkt.proto_display)
                info = (
                    str(pkt.app_details.get("request", pkt.summary[:60]))
                    if pkt.app_details
                    else pkt.summary[:60]
                )
                row = [
                    Text("▶", style=Style(color="#bf00ff")),
                    Text(pkt.time_str, style=style),
                    Text(pkt.src_display, style=style),
                    Text(pkt.dst_display, style=style),
                    Text(pkt.proto_display, style=Style(bold=True)),
                    Text(str(pkt.size), style=Style(color="#00ff41")),
                    Text(info[:50], style=Style(color="#808080")),
                ]
                self._table.add_row(*row, key=str(i))
        self._dirty = False

    @staticmethod
    def _protocol_style(proto: str) -> Style:
        colors = {
            "TCP": "#00ff41", "UDP": "#00ffff", "DNS": "#ffff00",
            "HTTP": "#ff8c00", "HTTPS": "#00ff88", "ARP": "#ff69b4",
            "ICMP": "#ff0040", "DHCP": "#9370db", "NTP": "#ff69b4",
            "SSH": "#00ff41", "MDNS": "#9370db",
        }
        return Style(color=colors.get(proto.upper(), "#808080"))
