from __future__ import annotations

import time
from typing import Optional

from textual.widget import Widget
from textual.widgets import Static
from textual.containers import Horizontal, Vertical

from netghost.i18n import t


class Dashboard(Widget):

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.total_packets = 0
        self.total_bytes = 0
        self.pkt_rate = 0.0
        self.byte_rate = 0.0
        self.active_conns = 0
        self.start_time = time.time()
        self._last_tick = time.time()
        self._tick_packets = 0
        self._tick_bytes = 0
        self._pkts_w: Optional[Static] = None
        self._bytes_w: Optional[Static] = None
        self._pktrate_w: Optional[Static] = None
        self._byterate_w: Optional[Static] = None
        self._conns_w: Optional[Static] = None
        self._uptime_w: Optional[Static] = None

    def compose(self):
        yield Static(t("dashboard.title"), id="dash-title")
        with Vertical(id="dash-body"):
            yield self._row("pkts", t("dashboard.pkts"), "0")
            yield self._row("bytes", t("dashboard.bytes"), "0 B")
            yield self._row("pktrate", t("dashboard.rate"), "0 pkts/s")
            yield self._row("byterate", t("dashboard.bw"), "0 MB/s")
            yield self._row("conns", t("dashboard.conns"), "0")
            yield self._row("uptime", t("dashboard.uptime"), "00:00:00")

    def _row(self, id_suffix: str, label: str, value: str) -> Widget:
        return Horizontal(
            Static(label, classes="dash-label"),
            Static(value, id=f"dash-{id_suffix}", classes="dash-value"),
            classes="dash-row",
        )

    def on_mount(self) -> None:
        self._pkts_w = self.query_one("#dash-pkts", Static)
        self._bytes_w = self.query_one("#dash-bytes", Static)
        self._pktrate_w = self.query_one("#dash-pktrate", Static)
        self._byterate_w = self.query_one("#dash-byterate", Static)
        self._conns_w = self.query_one("#dash-conns", Static)
        self._uptime_w = self.query_one("#dash-uptime", Static)

    def update_stats(self, pkt_size: int, conn_count: int) -> None:
        now = time.time()
        self.total_packets += 1
        self.total_bytes += pkt_size
        self._tick_packets += 1
        self._tick_bytes += pkt_size
        self.active_conns = conn_count

        if now - self._last_tick >= 1.0:
            elapsed = now - self._last_tick
            self.pkt_rate = self._tick_packets / elapsed
            self.byte_rate = (self._tick_bytes / elapsed) / (1024 * 1024)
            self._tick_packets = 0
            self._tick_bytes = 0
            self._last_tick = now

        uptime = int(time.time() - self.start_time)
        h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

        if self._pkts_w:
            self._pkts_w.update(self._fmt(self.total_packets))
        if self._bytes_w:
            self._bytes_w.update(self._fmt_bytes(self.total_bytes))
        if self._pktrate_w:
            self._pktrate_w.update(f"{self.pkt_rate:.1f} pkts/s")
        if self._byterate_w:
            self._byterate_w.update(f"{self.byte_rate:.2f} MB/s")
        if self._conns_w:
            self._conns_w.update(str(self.active_conns))
        if self._uptime_w:
            self._uptime_w.update(f"{h:02d}:{m:02d}:{s:02d}")

    @staticmethod
    def _fmt(n: int) -> str:
        if n < 1000:
            return str(n)
        if n < 1_000_000:
            return f"{n/1000:.1f}K"
        return f"{n/1_000_000:.1f}M"

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b < 1024:
            return f"{b}B"
        if b < 1048576:
            return f"{b/1024:.1f}KB"
        if b < 1073741824:
            return f"{b/1048576:.1f}MB"
        return f"{b/1073741824:.1f}GB"
