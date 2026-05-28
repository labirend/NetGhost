from __future__ import annotations

from typing import Optional

from textual.widgets import DataTable
from textual.widget import Widget
from rich.text import Text
from rich.style import Style

from netghost.models.packet import PacketInfo
from netghost.i18n import t


class TrafficTable(Widget):
    """Live traffic table with expandable packet rows."""

    MAX_ROWS = 500

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._packets: list[PacketInfo] = []
        self._table: Optional[DataTable] = None

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
        yield table

    def on_mount(self) -> None:
        self._table = self.query_one(DataTable)

    def get_table(self) -> Optional[DataTable]:
        return self._table

    def get_packet(self, index: int) -> Optional[PacketInfo]:
        try:
            return self._packets[index]
        except IndexError:
            return None

    def add_packet(self, pkt: PacketInfo) -> None:
        if len(self._packets) >= self.MAX_ROWS:
            self._packets.pop(0)
            if self._table and self._table.row_count > 0:
                self._table.remove_row(self._table.rows[0].key)

        self._packets.append(pkt)
        row_index = len(self._packets) - 1

        style = self._protocol_style(pkt.proto_display)
        expand_icon = "▶" if not pkt.expanded else "▼"

        info = ""
        if pkt.app_details:
            info = str(pkt.app_details.get("request", pkt.summary[:60]))
        else:
            info = pkt.summary[:60]

        row = [
            Text(expand_icon, style=Style(color="#bf00ff")),
            Text(pkt.time_str, style=style),
            Text(pkt.src_display, style=style),
            Text(pkt.dst_display, style=style),
            Text(pkt.proto_display, style=Style(bold=True)),
            Text(str(pkt.size), style=Style(color="#00ff41")),
            Text(info[:50], style=Style(color="#808080")),
        ]

        if self._table:
            self._table.add_row(*row, key=str(row_index))

    @staticmethod
    def _protocol_style(proto: str) -> Style:
        colors = {
            "TCP": "#00ff41",
            "UDP": "#00ffff",
            "DNS": "#ffff00",
            "HTTP": "#ff8c00",
            "HTTPS": "#00cc66",
            "ARP": "#ff69b4",
            "ICMP": "#ff0040",
            "DHCP": "#9370db",
            "NTP": "#ff69b4",
            "SSH": "#00ff41",
        }
        color = colors.get(proto.upper(), "#808080")
        return Style(color=color)
