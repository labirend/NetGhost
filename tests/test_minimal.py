"""Minimal Textual test — run inside container to isolate Docker+Textual issue."""
from textual.app import App
from textual.widgets import Label


class MinimalApp(App):
    def compose(self):
        yield Label("NetGhost Minimal Test — If you see this, Textual works in Docker.")


if __name__ == "__main__":
    print("Starting minimal Textual test...")
    MinimalApp().run()
    print("Minimal test exited.")
