from __future__ import annotations

import asyncio
import os
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Label, Static, DataTable, Button

from netghost.i18n import t
from netghost.capture.engine import CaptureEngine
from netghost.capture.recorder import PcapRecorder
from netghost.capture.interceptor import Interceptor
from netghost.models.packet import PacketInfo
from netghost.ui.widgets.interface_bar import InterfaceBar
from netghost.ui.widgets.traffic_table import TrafficTable
from netghost.ui.widgets.connection_panel import ConnectionPanel
from netghost.ui.widgets.dashboard import Dashboard


FILTER_GROUPS = [
    ["ALL", "TCP", "UDP", "DNS", "HTTP"],
    ["HTTPS", "ICMP", "ARP", "SSH", "DHCP"],
]


class MainScreen(Screen):
    BINDINGS = [
        ("s", "toggle_recording", "Record"),
        ("r", "send_rst", "Reset"),
        ("b", "block_connection", "Block"),
        ("space", "toggle_pause", "⏸"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.capture_engine = CaptureEngine()
        self.recorder = PcapRecorder()
        self.interceptor = Interceptor()
        self._capture_task: Optional[asyncio.Task] = None
        self._recording = False
        self._paused = False
        self._traffic_table: Optional[TrafficTable] = None
        self._conn_panel: Optional[ConnectionPanel] = None
        self._dashboard: Optional[Dashboard] = None

    def compose(self) -> ComposeResult:
        yield InterfaceBar()
        with Horizontal(id="content-row"):
            with Vertical(id="left-col"):
                yield Dashboard(id="dash-panel")
                with Vertical(id="filter-row"):
                    for group in FILTER_GROUPS:
                        with Horizontal(classes="filter-line"):
                            for f in group:
                                cls = "filter-btn active" if f == "ALL" else "filter-btn"
                                yield Button(f, id=f"flt-{f.lower()}", classes=cls)
                yield Button("■  STOP", id="pause-btn", classes="pause-btn-bottom paused")
            with Vertical(id="right-col"):
                with Vertical(classes="panel", id="traffic-panel"):
                    yield Label(t("traffic.title"), classes="panel-title")
                    yield TrafficTable()
                with Vertical(classes="panel", id="connection-panel"):
                    yield Label(t("connections.title"), classes="panel-title")
                    yield ConnectionPanel()
        with Horizontal(id="bottom-bar"):
            yield Static(t("key.help"), id="key-hints")

    async def on_mount(self) -> None:
        self._traffic_table = self.query_one(TrafficTable)
        self._conn_panel = self.query_one(ConnectionPanel)
        self._dashboard = self.query_one(Dashboard)

        iface_bar = self.query_one(InterfaceBar)
        iface = self.capture_engine.interface
        iface_bar.set_interface(iface)

        ip, mac = self.capture_engine.get_interface_info()
        iface_bar.set_ip_mac(ip, mac)

        force_test = os.environ.get("NETGHOST_DEV", "0") == "1"
        if force_test:
            iface_bar.set_test_mode()
            iface_bar.set_ip_mac("192.168.1.100", "00:1a:2b:3c:4d:5e")

        self._capture_task = asyncio.create_task(
            self._run_capture(force_test)
        )

    async def _run_capture(self, force_test: bool = False) -> None:
        ok = await self.capture_engine.start(force_test=force_test)
        if not ok and not force_test:
            msg = f"Capture failed — interface '{self.capture_engine.interface}' got no packets."
            self.notify(msg, severity="error", timeout=8)
        while True:
            try:
                pkt = await self.capture_engine.queue.get()
                if not self._paused:
                    self.process_packet(pkt)
            except asyncio.CancelledError:
                break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if not event.button.id:
            return
        if event.button.id.startswith("flt-"):
            filter_name = str(event.button.label).upper()
            for btn in self.query(".filter-btn"):
                btn.remove_class("active")
            event.button.add_class("active")
            if self._traffic_table:
                self._traffic_table.set_filter(filter_name)
        elif event.button.id == "pause-btn":
            self.action_toggle_pause()

    def process_packet(self, pkt: PacketInfo) -> None:
        if self._traffic_table:
            self._traffic_table.add_packet(pkt)
        if self._conn_panel:
            self._conn_panel.update(pkt)
        if self._dashboard:
            conn_count = self._conn_panel.flow_count if self._conn_panel else 0
            self._dashboard.update_stats(pkt.size, conn_count)
        self.recorder.add_packet(pkt)

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        btn = self.query_one("#pause-btn", Button)
        if self._paused:
            btn.label = "▶  START"
            btn.classes = "pause-btn-bottom"
            self.notify("Paused — scroll freely")
        else:
            btn.label = "■  STOP"
            btn.classes = "pause-btn-bottom paused"
            self.notify("Resumed")

    def action_toggle_recording(self) -> None:
        if not self.recorder.recording:
            filename = self.recorder.start()
            self._recording = True
            indicator = self.query_one("#recording-indicator", Static)
            indicator.update(f" ● {t('recording.active')} ")
            self.notify(t("recording.start"))
        else:
            filepath = self.recorder.stop()
            self._recording = False
            indicator = self.query_one("#recording-indicator", Static)
            indicator.update("")
            if filepath:
                self.notify(f"{t('recording.stop')}: {filepath}")
            else:
                self.notify(t("recording.stop"))

    def _get_selected_packet(self) -> Optional[PacketInfo]:
        if not self._traffic_table:
            return None
        table = self._traffic_table.get_table()
        if table and table.cursor_row is not None:
            return self._traffic_table.get_packet(table.cursor_row)
        return None

    def action_send_rst(self) -> None:
        pkt = self._get_selected_packet()
        if pkt and pkt.l4 and pkt.l4.protocol == "TCP":
            if self.interceptor.send_rst(pkt):
                self.notify(t("action.reset_sent"))
            else:
                self.notify("TCP reset failed", severity="error")
        else:
            self.notify("Select a TCP packet first", severity="warning")

    def action_block_connection(self) -> None:
        pkt = self._get_selected_packet()
        if pkt and pkt.l3:
            ip = pkt.l3.src_ip
            self.interceptor.block_ip(ip)
            self.notify(f"{t('action.blocked')}: {ip}")
        else:
            self.notify("Select a packet first", severity="warning")

    async def cleanup(self) -> None:
        self.capture_engine.stop()
        if self._capture_task:
            self._capture_task.cancel()
