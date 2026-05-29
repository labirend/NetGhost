from __future__ import annotations

from textual.widgets import Static
from textual.widget import Widget
from textual.containers import Horizontal
from rich.text import Text
from rich.style import Style


class InterfaceBar(Widget):
    """Top bar: shield logo + interface | IP | MAC | recording."""

    DEFAULT_CSS = """
    InterfaceBar {
        dock: top;
        height: 3;
        background: #0d0d0a;
        border-bottom: solid #00ffff;
        layout: horizontal;
    }
    #bar-left { width: 1fr; layout: horizontal; align: left middle; }
    #bar-mid  { width: 2fr; layout: horizontal; align: center middle; }
    #bar-right { width: 1fr; layout: horizontal; align: right middle; }
    """

    def compose(self):
        with Horizontal(id="bar-left"):
            logo = Text()
            logo.append("\u26e8 ", style=Style(color="#ff8c00", bold=True))
            logo.append("NetGhost", style=Style(color="#00ffff", bold=True))
            logo.append(" v0.1.0", style=Style(color="#606060"))
            yield Static(logo, id="app-title")
            yield Static("", id="interface-label")
        with Horizontal(id="bar-mid"):
            yield Static("", id="ip-label")
            yield Static("", id="mac-label")
        with Horizontal(id="bar-right"):
            yield Static("", id="recording-indicator")

    def set_interface(self, iface: str) -> None:
        self.query_one("#interface-label", Static).update(f" [{iface}] ")

    def set_ip_mac(self, ip: str, mac: str) -> None:
        ip_t = Text()
        ip_t.append(f"IP:{ip}", style=Style(color="#00ff41", bold=True))
        ip_t.append(" \u2502 ", style=Style(color="#444444"))
        ip_t.append(f"MAC:{mac}", style=Style(color="#ff8c00", bold=True))
        self.query_one("#ip-label", Static).update(ip_t)
        self.query_one("#mac-label", Static).update("")

    def set_test_mode(self) -> None:
        self.query_one("#interface-label", Static).update(" [TEST MODE] ")
        self.query_one("#app-title", Static).update(
            Text()
            .append("\u26e8 ", style=Style(color="#ff8c00", bold=True))
            .append("NetGhost", style=Style(color="#00ffff", bold=True))
            .append(" \u2014 Demo", style=Style(color="#bf00ff"))
        )
