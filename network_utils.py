"""
============================================================================
 AVISO ETICO / LEGAL
 Este modulo forma parte de una herramienta de pentesting.
 Uso EXCLUSIVO en sistemas para los que se tenga autorizacion explicita
 (contrato de auditoria, programa de bug bounty, laboratorio propio, CTF).
 Queda PROHIBIDO su uso contra sistemas de terceros sin permiso.
 El autor no se hace responsable del mal uso de este software.
============================================================================

Funciones comunes que van a usar todos los plugins:
- request seguro (maneja timeouts, ssl roto, redirecciones raras)
- eleccion de un User-Agent random para no parecer siempre el mismo bot
- una pausa entre peticiones para no saturar el servidor (anti rate-limit)
"""

import time
import random
import requests

# Lista simple de user agents, no hace falta nada mas sofisticado
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def get_random_headers():
    """Devuelve un header con un User-Agent random, asi cada peticion
    no parece que vaya siempre firmada por el mismo cliente."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }


def safe_request(metodo, url, delay=1.0, timeout=8, max_redirects=5, **kwargs):
    """
    Wrapper de requests que centraliza el manejo de errores para que
    los plugins no tengan que repetir el mismo try/except cien veces.

    Devuelve una tupla (response, error) -> si algo falla, response es None
    y error trae el mensaje explicando que paso.
    """
    # pausa anti flood / anti WAF antes de disparar la peticion
    time.sleep(delay)

    headers = kwargs.pop("headers", {})
    headers.update(get_random_headers())

    session = kwargs.pop("session", None) or requests

    try:
        resp = session.request(
            metodo,
            url,
            headers=headers,
            timeout=timeout,
            verify=True,  # empezamos verificando SSL de forma normal
            allow_redirects=True,
            **kwargs,
        )
        # cortamos manualmente si hay demasiadas redirecciones en el historial
        if len(resp.history) > max_redirects:
            return None, f"Demasiadas redirecciones ({len(resp.history)}) en {url}"
        return resp, None

    except requests.exceptions.SSLError:
        # reintentamos una vez sin verificar el certificado, pero avisando
        try:
            resp = session.request(
                metodo, url, headers=headers, timeout=timeout,
                verify=False, allow_redirects=True, **kwargs,
            )
            return resp, "SSL invalido o autofirmado (se continuo sin verificar)"
        except requests.exceptions.RequestException as e:
            return None, f"Error SSL irrecuperable: {e}"

    except requests.exceptions.Timeout:
        return None, f"Timeout al conectar con {url}"

    except requests.exceptions.TooManyRedirects:
        return None, f"Bucle de redirecciones detectado en {url}"

    except requests.exceptions.ConnectionError as e:
        return None, f"Error de conexion: {e}"

    except requests.exceptions.RequestException as e:
        return None, f"Error inesperado de requests: {e}"


# ----------------------------------------------------------------------
# CRAWLER: descubre subpaginas del mismo dominio (ej: /login, /contacto)
# para que los plugins no se queden solo con la URL principal.
# ----------------------------------------------------------------------

# Extensiones que no tiene sentido "rastrear" como si fueran paginas,
# son recursos estaticos, no puntos de entrada con inputs
EXTENSIONES_A_IGNORAR = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".rar", ".mp4", ".mp3",
)


def _normalizar_url(url):
    """Quita el fragmento (#seccion) y la barra final sobrante, para que
    no contemos la misma pagina dos veces con nombres ligeramente distintos."""
    from urllib.parse import urlparse, urlunparse
    partes = urlparse(url)
    limpia = partes._replace(fragment="")
    texto = urlunparse(limpia)
    return texto.rstrip("/")


def _es_mismo_dominio(url, dominio_base):
    from urllib.parse import urlparse
    return urlparse(url).netloc == dominio_base


def descubrir_paginas(url_inicial, session=None, delay=1.0, profundidad_maxima=1, max_paginas=12):
    """
    Rastrea el sitio a partir de url_inicial siguiendo enlaces <a href>
    que apunten al mismo dominio, hasta una profundidad y cantidad
    limitadas (para no convertir esto en un crawler descontrolado).

    Solo sigue enlaces, no envia formularios ni hace clic en botones,
    asi que sigue siendo un rastreo pasivo de solo lectura.

    Devuelve una lista de URLs unicas, incluyendo siempre la url_inicial.
    """
    from urllib.parse import urlparse, urljoin
    from bs4 import BeautifulSoup

    dominio_base = urlparse(url_inicial).netloc
    visitadas = set()
    por_visitar = [(url_inicial, 0)]  # (url, profundidad_actual)
    paginas_encontradas = []

    while por_visitar and len(paginas_encontradas) < max_paginas:
        url_actual, profundidad = por_visitar.pop(0)
        url_actual_normalizada = _normalizar_url(url_actual)

        if url_actual_normalizada in visitadas:
            continue
        visitadas.add(url_actual_normalizada)

        resp, error = safe_request("GET", url_actual, delay=delay, session=session)
        if error or resp is None:
            continue  # si una subpagina falla, seguimos con las demas

        paginas_encontradas.append(url_actual)

        if profundidad >= profundidad_maxima:
            continue  # no seguimos bajando mas de la profundidad pedida

        soup = BeautifulSoup(resp.text, "html.parser")
        for etiqueta_a in soup.find_all("a", href=True):
            href = etiqueta_a["href"].strip()

            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            if href.lower().endswith(EXTENSIONES_A_IGNORAR):
                continue

            url_absoluta = urljoin(url_actual, href)

            if not _es_mismo_dominio(url_absoluta, dominio_base):
                continue  # nos quedamos dentro del alcance, no seguimos enlaces externos

            url_absoluta_normalizada = _normalizar_url(url_absoluta)
            if url_absoluta_normalizada not in visitadas:
                por_visitar.append((url_absoluta, profundidad + 1))

    return paginas_encontradas


def porcentaje_similitud(texto_a, texto_b):
    """Compara dos textos y devuelve que tan parecidos son (0.0 a 1.0).
    Lo usamos para detectar anomalias en la respuesta aunque el payload
    no se refleje literal (por ejemplo si rompe el layout de la pagina
    o si cambia una parte grande del contenido)."""
    import difflib
    if not texto_a or not texto_b:
        return 0.0
    return difflib.SequenceMatcher(None, texto_a, texto_b).ratio()
