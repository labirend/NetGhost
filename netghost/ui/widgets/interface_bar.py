from __future__ import annotations

from textual.widgets import Static, Button
from textual.widget import Widget
from textual.containers import Horizontal

from netghost.i18n import t


class InterfaceBar(Widget):
    """Top bar with app title, interface, recording, language."""

    DEFAULT_CSS = """
    InterfaceBar {
        dock: top;
        height: 3;
        background: #0d0d0d;
        border-bottom: solid #00ffff;
        layout: horizontal;
        align: center middle;
    }
    """

    def compose(self):
        yield Static("NetGhost v0.1.0", id="app-title")
        yield Static("", id="interface-label")
        yield Static("", id="recording-indicator")
        yield Button("L", id="lang-button")

    def set_interface(self, iface: str) -> None:
        label = self.query_one("#interface-label", Static)
        label.update(f" [{iface}] ")

    def set_test_mode(self) -> None:
        label = self.query_one("#interface-label", Static)
        label.update(" [TEST MODE] ")
        title = self.query_one("#app-title", Static)
        title.update("NetGhost v0.1.0 — Demo")
