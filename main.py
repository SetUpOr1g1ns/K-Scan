import json
import datetime

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Button, Input, Static, RichLog
from textual import work

import requests

# Guardamos aqui todos los resultados que vayamos generando durante la sesion
INFORME = {
    "objetivo": None,
    "fecha": None,
    "resultados": [],
}


def importar_plugin(nombre_modulo, nombre_funcion="ejecutar_plugin"):
    try:
        # 1. Intentamos cargar el modulo desde la carpeta "Plugins"
        ruta_modulo = f"Plugins.{nombre_modulo}"
        modulo = __import__(ruta_modulo, fromlist=[nombre_funcion])
        
        # 2. Extraemos la funcion especifica del modulo cargado
        funcion = getattr(modulo, nombre_funcion)
        return funcion
        
    except (ImportError, AttributeError):
        # 3. Si el modulo no existe o la funcion no esta, devolvemos None
        print(funcion)
        return None



class PentestApp(App):
    """App principal de la TBI. Un boton por cada vector de ataque."""

    CSS = """
    Screen {
        align: center top;
    }
    #panel_botones {
        width: 30;
        padding: 1 2;
        border: round $accent;
    }
    #panel_log {
        border: round $accent;
        padding: 1 2;
    }
    Button {
        width: 100%;
        margin-bottom: 1;
    }
    #input_url {
        margin-bottom: 1;
    }
    """

    BINDINGS = [("q", "quit", "Salir")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="panel_botones"):
                yield Static("Objetivo (URL):")
                yield Input(placeholder="https://ejemplo.com", id="input_url")
                yield Button("Escanear Headers", id="btn_headers", variant="primary")
                yield Button("Buscar Archivos Expuestos", id="btn_exposed", variant="primary")
                yield Button("Probar XSS", id="btn_xss", variant="primary")
                yield Button("Probar SQLi", id="btn_sqli", variant="primary")
                yield Button("Ejecutar TODO", id="btn_todo", variant="warning")
                yield Button("Guardar informe JSON", id="btn_guardar", variant="success")
            with VerticalScroll(id="panel_log"):
                yield RichLog(id="log", wrap=True, highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        log = self.query_one("#log", RichLog)
        log.write("[bold yellow]=== Aviso etico ===[/bold yellow]")
        log.write("Usa esta herramienta solo en sistemas con autorizacion explicita.")
        log.write("Introduce la URL objetivo arriba y pulsa el vector que quieras probar.\n")

    def _obtener_url(self):
        """Lee la URL del input y la valida un poco antes de lanzar nada."""
        campo = self.query_one("#input_url", Input)
        url = campo.value.strip()
        log = self.query_one("#log", RichLog)

        if not url:
            log.write("[bold red]Error:[/bold red] no has puesto ninguna URL.")
            return None
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        return url

    def on_button_pressed(self, event: Button.Pressed) -> None:
        boton = event.button.id

        if boton == "btn_headers":
            self.lanzar_plugin("headers", "Cabeceras de seguridad")
        elif boton == "btn_exposed":
            self.lanzar_plugin("exposed_files", "Archivos expuestos")
        elif boton == "btn_xss":
            self.lanzar_plugin("xss", "Cross-Site Scripting")
        elif boton == "btn_sqli":
            self.lanzar_plugin("sqli", "SQL Injection")
        elif boton == "btn_todo":
            self.lanzar_todos()
        elif boton == "btn_guardar":
            self.guardar_informe()

    def lanzar_plugin(self, nombre_modulo, nombre_bonito):

        # 1. Obtener la URL escrita por el usuario
        url = self._obtener_url()

        # 2. Si la URL no es valida, cancelar
        if not url:
            return

        # 3. Ejecutar el plugin
        self.ejecutar_worker_plugin(
            nombre_modulo,
            nombre_bonito,
            url
        )

    def lanzar_todos(self):
        url = self._obtener_url()
        if not url:
            return
        for nombre_modulo, nombre_bonito in [
            ("headers", "Cabeceras de seguridad"),
            ("exposed_files", "Archivos expuestos"),
            ("xss", "Cross-Site Scripting"),
            ("sqli", "SQL Injection"),
        ]:
            self.ejecutar_worker_plugin(nombre_modulo, nombre_bonito, url)

    @work(thread=True)
    def ejecutar_worker_plugin(self, nombre_modulo, nombre_bonito, url):
        """Ejecuta el plugin en un hilo aparte para no congelar la interfaz
        mientras se hacen las peticiones HTTP (que tardan su tiempo)."""
        log = self.query_one("#log", RichLog)
        self.call_from_thread(log.write, f"\n[bold cyan]>> Lanzando: {nombre_bonito}...[/bold cyan]")

        funcion_plugin = importar_plugin(nombre_modulo)
        if funcion_plugin is None:
            self.call_from_thread(
                log.write,
                f"[bold red]El plugin '{nombre_modulo}' todavia no esta implementado.[/bold red]"
            )
            return

        try:
            # 1. Crear una sesion HTTP que reutilizaran las peticiones
            session = requests.Session()

            # 2. Ejecutar el plugin pasandole:
            #    - la URL
            #    - un retraso entre peticiones
            #    - la sesion HTTP
            resultado = funcion_plugin(
                url,
                delay=1.0,
                session=session
            )
        except Exception as e:
            resultado = {"plugin": nombre_modulo, "error_fatal": str(e)}
            self.call_from_thread(log.write, f"[bold red]Fallo inesperado en {nombre_modulo}: {e}[/bold red]")

        INFORME["objetivo"] = url
        INFORME["fecha"] = datetime.datetime.now().isoformat()
        INFORME["resultados"].append(resultado)

        self.call_from_thread(self._mostrar_resumen_plugin, nombre_bonito, resultado)

    def _mostrar_resumen_plugin(self, nombre_bonito, resultado):
        log = self.query_one("#log", RichLog)
        # Intentamos obtener la clave "vulnerable".
        # Si no existe, get() devolvera None.
        vulnerable = resultado.get("vulnerable")

        if vulnerable is True:
            log.write(f"[bold red]>> {nombre_bonito}: POSIBLE VULNERABILIDAD ENCONTRADA[/bold red]")
        elif vulnerable is False:
            log.write(f"[bold green]>> {nombre_bonito}: sin hallazgos relevantes[/bold green]")
        else:
            log.write(f"[bold yellow]>> {nombre_bonito}: finalizado (revisar detalle en JSON)[/bold yellow]")

        for error in resultado.get("errores", []):
            log.write(f"   [dim red]Aviso: {error}[/dim red]")

    def guardar_informe(self):
        log = self.query_one("#log", RichLog)
        if not INFORME["resultados"]:
            log.write("[bold red]No hay nada que guardar todavia, ejecuta algun plugin primero.[/bold red]")
            return

        try:
            with open("informe_pentest.json", "w", encoding="utf-8") as f:
                json.dump(INFORME, f, indent=2, ensure_ascii=False)
            log.write("[bold green]Informe guardado: [/bold green]")
        except Exception as e:
            log.write(f"[bold red]No se pudo guardar el informe: {e}[/bold red]")


if __name__ == "__main__":
    print("=" * 70)
    print(" HERRAMIENTA DE PENTESTING - USO EXCLUSIVO AUTORIZADO")
    print(" Asegurate de tener permiso explicito para probar el objetivo.")
    print("=" * 70)
    PentestApp().run()
