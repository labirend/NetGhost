from __future__ import annotations

from typing import Optional

from textual.widgets import DataTable
from textual.widget import Widget
from rich.text import Text
from rich.style import Style

from netghost.models.packet import PacketInfo
from netghost.i18n import t


class ConnectionPanel(Widget):
    """Displays active connections (aggregated flows)."""

    MAX_FLOWS = 100

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._flows: dict[str, dict] = {}
        self._table: Optional[DataTable] = None

    def compose(self):
        table = DataTable(id="connection-table")
        table.add_columns(
            t("connections.col.src"),
            t("connections.col.dst"),
            t("connections.col.proto"),
            t("connections.col.port"),
            t("connections.col.bytes"),
        )
        table.cursor_type = "row"
        table.show_cursor = True
        table.show_horizontal_scrollbar = True
        yield table

    def on_mount(self) -> None:
        self._table = self.query_one(DataTable)

    def update(self, pkt: PacketInfo) -> None:
        if not pkt.l3 or not pkt.l4:
            return

        src = pkt.l3.src_ip
        dst = pkt.l3.dst_ip
        key = f"{src}→{dst}"

        if key not in self._flows:
            if len(self._flows) >= self.MAX_FLOWS:
                oldest = min(self._flows, key=lambda k: self._flows[k]["last"])
                del self._flows[oldest]
                if self._table:
                    self._table.clear()

            self._flows[key] = {
                "src": src,
                "dst": dst,
                "proto": pkt.l4.protocol,
                "port": f"{pkt.l4.src_port}→{pkt.l4.dst_port}",
                "bytes": 0,
                "last": pkt.timestamp,
            }

        flow = self._flows[key]
        flow["bytes"] += pkt.size
        flow["last"] = pkt.timestamp

        self._refresh_display()

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    def _refresh_display(self) -> None:
        if not self._table:
            return
        self._table.clear()
        for flow in sorted(self._flows.values(), key=lambda f: f["last"], reverse=True)[:30]:
            style = Style(color="#00ffff")
            if flow["bytes"] > 10000:
                style = Style(color="#ff8c00")
            self._table.add_row(
                Text(flow["src"], style=style),
                Text(flow["dst"], style=style),
                Text(flow["proto"], style=Style(bold=True, color="#00ff41")),
                Text(flow["port"], style=Style(color="#808080")),
                Text(self._format_bytes(flow["bytes"]), style=Style(color="#00ff41")),
            )

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b}B"
        if b < 1048576:
            return f"{b/1024:.1f}KB"
        return f"{b/1048576:.1f}MB"
