"""Test: Does a Screen + containers work? (no CSS)"""
from textual.app import App
from textual.screen import Screen
from textual.containers import Horizontal, Vertical
from textual.widgets import Label, Static


class TestScreen(Screen):
    def compose(self):
        yield Label("Top Bar — NetGhost v0.1.0", id="app-title")
        with Horizontal(id="middle-row"):
            with Vertical(classes="panel", id="left-panel"):
                yield Label("Traffic Panel", classes="panel-title")
                yield Static("Packet list would be here")
            with Vertical(classes="panel", id="right-panel"):
                yield Label("Connections Panel", classes="panel-title")
                yield Static("Flow data would be here")
        yield Static("Stats panel — pkts: 0 | rate: 0/s", id="stats")
        yield Static("Detail panel — select a packet", id="detail")
        yield Static("S:Record  R:RST  B:Block  L:Lang  Q:Quit", id="key-hints")


class TestApp(App):
    def compose(self):
        yield TestScreen()


if __name__ == "__main__":
    TestApp().run()
