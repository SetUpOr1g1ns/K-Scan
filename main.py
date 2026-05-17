from textual.app import App
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, Button, Input, Checkbox


class LayoutApp(App):

    CSS = """
    Screen {
        background: black;
        layout: vertical;
    }

    #main {
        height: 1fr;
    }

    #left {
        width: 75%;
        border: round green;
        content-align: center middle;
    }

    #right {
        width: 25%;
        padding: 1;
    }

    .row {
        height: auto;
        padding: 1;
    }

    #url_input {
        height: auto;
        padding: 1;
    }

    Input {
        width: 1fr;
        margin-right: 1;
    }

    Button {
        width: 12;
    }
    """

    def compose(self):
        plugins: list = [
            "cookies",
            "exposed_files",
            "headers",
            "exposed_data",
            "sql_injections",
            "xss",
        ]

        
        # Layout
        with Horizontal(id="main"):
            yield Static("Drawing", id="left")

            with Vertical(id="right"):
                for plugin in plugins:
                    with Horizontal(classes="row"):
                        yield Checkbox(plugin)

        with Horizontal(id="url_input"):
            yield Input(placeholder="Introduce a target")
            yield Button("Scan")


if __name__ == "__main__":
    LayoutApp().run()