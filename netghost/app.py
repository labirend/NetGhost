from __future__ import annotations

from textual.app import App
from textual.binding import Binding
from textual.widgets import Static

from netghost.ui.screens.main_screen import MainScreen
from netghost.i18n import set_language, t


class NetGhostApp(App):
    CSS_PATH = "ui/css/cyberpunk.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("l", "toggle_language", "Lang"),
    ]

    def compose(self):
        return iter([])

    def on_mount(self) -> None:
        self.push_screen(MainScreen())

    def action_quit(self) -> None:
        self.exit()

    def action_toggle_language(self) -> None:
        from netghost.i18n import get_language
        current = get_language()
        new = "tr" if current == "en" else "en"
        set_language(new)
        self.notify(f"Language: {'Türkçe' if new == 'tr' else 'English'}")
        hint = self.screen.query_one("#key-hints", Static)
        hint.update(t("key.help"))


def main() -> None:
    import sys
    try:
        app = NetGhostApp()
        app.run()
    except Exception as e:
        print(f"\nNetGhost Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
