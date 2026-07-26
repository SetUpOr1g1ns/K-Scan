"""
============================================================================
 AVISO ETICO / LEGAL
 Plugin de verificacion de cabeceras de seguridad HTTP.
 Uso EXCLUSIVO en sistemas para los que se tenga autorizacion explicita.
 Este plugin es 100% pasivo: solo hace un GET normal y lee las cabeceras
 de la respuesta, no envia payloads ni modifica nada en el servidor.
 Prohibido su uso contra sistemas de terceros sin permiso.
============================================================================

Plugin mas sencillo de todos. La idea es simple:
1. Hacemos una peticion GET normal a la URL.
2. Miramos que cabeceras de seguridad trae (o no trae) la respuesta.
3. Por cada cabecera que falte, lo apuntamos como un hallazgo.

Cabeceras que revisamos:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
"""

from network_utils import safe_request

# Diccionario con la cabecera y una explicacion corta de para que sirve,
# asi el informe final se entiende sin tener que buscar en google
CABECERAS_A_REVISAR = {
    "Content-Security-Policy": (
        "Sin CSP el navegador no restringe que scripts/recursos se pueden "
        "cargar, lo que facilita ataques XSS."
    ),
    "Strict-Transport-Security": (
        "Sin HSTS el navegador puede seguir aceptando conexiones HTTP, "
        "abriendo la puerta a ataques de downgrade o man-in-the-middle."
    ),
    "X-Content-Type-Options": (
        "Sin 'nosniff' el navegador puede intentar adivinar el tipo de "
        "archivo y ejecutar contenido que no deberia (MIME sniffing)."
    ),
    "X-Frame-Options": (
        "Sin esta cabecera (o una CSP con frame-ancestors) la pagina se "
        "puede meter dentro de un iframe ajeno, abriendo la puerta a "
        "ataques de clickjacking."
    ),
}


def _revisar_csp_en_frame_ancestors(headers):
    """A veces el clickjacking ya esta cubierto por la CSP en vez de por
    X-Frame-Options directamente (con la directiva frame-ancestors).
    Miramos si es el caso antes de marcarlo como hallazgo."""
    csp = headers.get("Content-Security-Policy", "")
    return "frame-ancestors" in csp.lower()


def ejecutar_plugin(url, delay=1.0, session=None):
    """
    Punto de entrada del plugin, igual que en xss.py.
    Devuelve un diccionario para el informe final.
    """
    resultado = {
        "plugin": "headers",
        "url_objetivo": url,
        "hallazgos": [],
        "cabeceras_presentes": {},
        "vulnerable": False,
        "errores": [],
    }

    resp, error = safe_request("GET", url, delay=delay, session=session)
    if error:
        resultado["errores"].append(error)
        return resultado

    headers_respuesta = resp.headers  # esto ya viene case-insensitive de requests
    resultado["cabeceras_presentes"] = dict(headers_respuesta)

    for nombre_cabecera, explicacion in CABECERAS_A_REVISAR.items():
        presente = nombre_cabecera in headers_respuesta

        # caso especial: X-Frame-Options puede estar cubierto por CSP
        if nombre_cabecera == "X-Frame-Options" and not presente:
            if _revisar_csp_en_frame_ancestors(headers_respuesta):
                resultado["hallazgos"].append({
                    "cabecera": nombre_cabecera,
                    "falta": False,
                    "nota": "Cubierta indirectamente por CSP (frame-ancestors)",
                })
                continue

        if not presente:
            resultado["hallazgos"].append({
                "cabecera": nombre_cabecera,
                "falta": True,
                "riesgo": explicacion,
            })
        else:
            resultado["hallazgos"].append({
                "cabecera": nombre_cabecera,
                "falta": False,
                "valor": headers_respuesta.get(nombre_cabecera),
            })

    resultado["vulnerable"] = any(h.get("falta") for h in resultado["hallazgos"])
    resultado["codigo_http"] = resp.status_code

    return resultado


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Uso: python headers.py <url>")
        sys.exit(1)

    salida = ejecutar_plugin(sys.argv[1])
    print(json.dumps(salida, indent=2, ensure_ascii=False))
