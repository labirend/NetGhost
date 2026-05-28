from __future__ import annotations

import time

from textual.widgets import Static, RichLog
from textual.widget import Widget
from textual.containers import Horizontal
from rich.text import Text
from rich.style import Style

from netghost.i18n import t


class StatsPanel(Widget):
    """Bottom statistics bar showing real-time metrics."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self._last_tick = time.time()
        self._tick_packets = 0
        self._tick_bytes = 0
        self._pkt_rate = 0.0
        self._byte_rate = 0.0
        self._active_conns = 0

    def compose(self):
        with Horizontal(id="stats-container"):
            yield self._stat_box("pkts_total", t("stats.pkts"), "0")
            yield self._stat_box("pkts_rate", t("stats.pkts_per_sec"), "0")
            yield self._stat_box("byte_rate", t("stats.bytes_per_sec"), "0.0")
            yield self._stat_box("total_bytes", t("stats.total"), "0 B")
            yield self._stat_box("active_conns", t("stats.active_conns"), "0")
            yield self._stat_box("uptime", t("stats.uptime"), "00:00:00")

    def _stat_box(self, id_suffix: str, label: str, value: str):
        from textual.containers import Vertical
        from textual.widgets import Static
        return Vertical(
            Static(value, id=f"stat-val-{id_suffix}", classes="stat-value"),
            Static(label, classes="stat-label"),
            classes="stat-box",
        )

    def tick(self, packet_size: int) -> None:
        now = time.time()
        self.total_packets += 1
        self.total_bytes += packet_size
        self._tick_packets += 1
        self._tick_bytes += packet_size

        if now - self._last_tick >= 1.0:
            elapsed = now - self._last_tick
            self._pkt_rate = self._tick_packets / elapsed
            self._byte_rate = (self._tick_bytes / elapsed) / (1024 * 1024)
            self._tick_packets = 0
            self._tick_bytes = 0
            self._last_tick = now
            self._update_display()

    def set_active_connections(self, count: int) -> None:
        self._active_conns = count

    def _update_display(self) -> None:
        uptime = int(time.time() - self.start_time)
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        seconds = uptime % 60

        values = {
            "pkts_total": str(self.total_packets),
            "pkts_rate": f"{self._pkt_rate:.1f}",
            "byte_rate": f"{self._byte_rate:.2f}",
            "total_bytes": self._format_bytes(self.total_bytes),
            "active_conns": str(self._active_conns),
            "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        }

        for key, val in values.items():
            widget = self.query_one(f"#stat-val-{key}")
            if widget:
                widget.update(val)

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b}B"
        if b < 1048576:
            return f"{b/1024:.1f}KB"
        if b < 1073741824:
            return f"{b/1048576:.1f}MB"
        return f"{b/1073741824:.1f}GB"
