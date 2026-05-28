from __future__ import annotations

import asyncio
import os
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Label, Static, DataTable

from netghost.i18n import t
from netghost.capture.engine import CaptureEngine
from netghost.capture.recorder import PcapRecorder
from netghost.capture.interceptor import Interceptor
from netghost.models.packet import PacketInfo
from netghost.ui.widgets.interface_bar import InterfaceBar
from netghost.ui.widgets.traffic_table import TrafficTable
from netghost.ui.widgets.connection_panel import ConnectionPanel
from netghost.ui.widgets.stats_panel import StatsPanel
from netghost.ui.widgets.detail_panel import DetailPanel


class MainScreen(Screen):
    BINDINGS = [
        ("s", "toggle_recording", "Record"),
        ("r", "send_rst", "RST"),
        ("b", "block_connection", "Block"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.capture_engine = CaptureEngine()
        self.recorder = PcapRecorder()
        self.interceptor = Interceptor()
        self._capture_task: Optional[asyncio.Task] = None
        self._recording = False
        self._traffic_table: Optional[TrafficTable] = None
        self._conn_panel: Optional[ConnectionPanel] = None
        self._stats_panel: Optional[StatsPanel] = None
        self._detail_panel: Optional[DetailPanel] = None

    def compose(self) -> ComposeResult:
        yield InterfaceBar()
        with Horizontal(id="middle-row"):
            with Vertical(classes="panel", id="traffic-panel"):
                yield Label(t("traffic.title"), classes="panel-title")
                yield TrafficTable()
            with Vertical(classes="panel", id="connection-panel"):
                yield Label(t("connections.title"), classes="panel-title")
                yield ConnectionPanel()
        yield StatsPanel(id="stats-panel")
        yield DetailPanel(id="detail-container")
        yield Static(t("key.help"), id="key-hints")

    def on_mount(self) -> None:
        self._traffic_table = self.query_one(TrafficTable)
        self._conn_panel = self.query_one(ConnectionPanel)
        self._stats_panel = self.query_one(StatsPanel)
        self._detail_panel = self.query_one(DetailPanel)

        interface = self.query_one(InterfaceBar)
        iface = self.capture_engine.interface
        interface.set_interface(iface)

        force_test = os.environ.get("NETGHOST_DEV", "0") == "1"
        self._capture_task = asyncio.create_task(
            self._run_capture(force_test)
        )

    async def _run_capture(self, force_test: bool = False) -> None:
        await self.capture_engine.start(force_test=force_test)
        if self.capture_engine.is_test_mode:
            self.query_one(InterfaceBar).set_test_mode()
        while True:
            try:
                pkt = await self.capture_engine.queue.get()
                self.process_packet(pkt)
            except asyncio.CancelledError:
                break

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not self._detail_panel or not self._traffic_table:
            return
        try:
            row_key = event.row_key.value
            if row_key is None:
                return
            row_index = int(row_key)
            pkt = self._traffic_table.get_packet(row_index)
            if pkt:
                self._detail_panel.show_packet(pkt)
        except (ValueError, IndexError):
            pass

    def process_packet(self, pkt: PacketInfo) -> None:
        if self._traffic_table:
            self._traffic_table.add_packet(pkt)
        if self._conn_panel:
            self._conn_panel.update(pkt)
        if self._stats_panel:
            self._stats_panel.tick(pkt.size)
        self.recorder.add_packet(pkt)

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
                self.notify("RST failed", severity="error")
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
