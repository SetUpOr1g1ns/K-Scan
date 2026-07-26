"""
============================================================================
 AVISO ETICO / LEGAL
 Plugin de deteccion de archivos y rutas expuestas (.env, .git, backups...).
 Uso EXCLUSIVO en sistemas para los que se tenga autorizacion explicita.
 Este plugin solo hace peticiones GET de lectura a rutas conocidas,
 no descarga contenido sensible completo ni modifica nada.
 Prohibido su uso contra sistemas de terceros sin permiso.
============================================================================

El problema de este tipo de escaneo es que muchas webs devuelven
codigo 200 para TODO, incluso para rutas que no existen (paginas de
error personalizadas tipo "not found" pero con status 200). Si no
controlamos esto, el plugin diria que ha encontrado 40 archivos
"expuestos" cuando en realidad no ha encontrado ninguno.

Solucion: antes de probar nada, pedimos una ruta que sabemos que es
inventada (un nombre random que no va a existir nunca) y guardamos
como es esa respuesta "fantasma". Luego, cada vez que probamos una
ruta real, comparamos contra esa respuesta fantasma. Si se parecen
demasiado, lo tratamos como falso positivo y no como hallazgo real.
"""

import random
import string
import hashlib

from network_utils import safe_request

# Rutas tipicas que se suelen dejar expuestas por descuido
RUTAS_SENSIBLES = [
    ".env",
    ".env.local",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    "wp-config.php",
    "wp-config.php.bak",
    "config.php.bak",
    "backup.zip",
    "backup.sql",
    "db_backup.sql",
    "database.sql",
    "site_backup.tar.gz",
    ".DS_Store",
    "web.config",
    "composer.json",
    "package.json",
    ".htaccess",
]

# Palabras que si aparecen en el contenido nos dan bastante confianza
# de que el archivo es real y no una pagina de error disfrazada
PISTAS_CONTENIDO_REAL = {
    ".env": ["DB_", "API_KEY", "SECRET", "PASSWORD"],
    "wp-config.php": ["DB_NAME", "DB_USER", "wp_"],
    ".git/config": ["[core]", "repositoryformatversion"],
    ".git/HEAD": ["ref:"],
}


def _generar_ruta_inventada():
    """Genera un nombre de archivo random que casi seguro no existe,
    para usarlo como 'control' contra falsos positivos."""
    nombre_random = "".join(random.choices(string.ascii_lowercase, k=20))
    return f"{nombre_random}.bak"


def _huella_respuesta(resp):
    """Crea una huella simple de la respuesta (tamano + hash del cuerpo)
    para poder comparar rapido si dos respuestas son practicamente
    identicas, sin tener que comparar el texto entero cada vez."""
    cuerpo = resp.text or ""
    return {
        "status": resp.status_code,
        "tamano": len(cuerpo),
        "hash": hashlib.md5(cuerpo.encode("utf-8", errors="ignore")).hexdigest(),
    }


def _parece_falso_positivo(huella_ruta, huella_fantasma):
    """Compara la respuesta de la ruta real contra la respuesta 'fantasma'
    (la que sabemos que no deberia existir). Si son casi iguales, es
    una pagina de error personalizada devolviendo 200 para todo."""
    if huella_ruta["hash"] == huella_fantasma["hash"]:
        return True
    # si el tamano es practicamente identico (menos de un 3% de diferencia)
    # tambien lo tratamos como sospechoso de ser la misma pagina de error
    if huella_fantasma["tamano"] > 0:
        diferencia = abs(huella_ruta["tamano"] - huella_fantasma["tamano"])
        porcentaje_diferencia = diferencia / huella_fantasma["tamano"]
        if porcentaje_diferencia < 0.03:
            return True
    return False


def _tiene_contenido_creible(ruta, texto):
    """Si tenemos pistas de contenido para esta ruta, comprobamos que
    al menos una aparezca. Esto nos da mas confianza todavia."""
    pistas = PISTAS_CONTENIDO_REAL.get(ruta)
    if not pistas:
        return None  # no tenemos pistas para esta ruta, no opinamos
    return any(pista in texto for pista in pistas)


def ejecutar_plugin(url, delay=1.0, session=None):
    """
    Punto de entrada del plugin.
    Primero calibra con una ruta inventada, luego prueba las rutas reales.
    """
    resultado = {
        "plugin": "exposed_files",
        "url_objetivo": url,
        "hallazgos": [],
        "vulnerable": False,
        "errores": [],
    }

    url_base = url.rstrip("/")

    # Paso 1: calibracion anti falso-positivo con una ruta inventada
    ruta_fantasma = _generar_ruta_inventada()
    resp_fantasma, error = safe_request("GET", f"{url_base}/{ruta_fantasma}", delay=delay, session=session)
    if error:
        resultado["errores"].append(f"No se pudo calibrar falsos positivos: {error}")
        huella_fantasma = None
    else:
        huella_fantasma = _huella_respuesta(resp_fantasma)

    # Paso 2: probar cada ruta sensible de verdad
    for ruta in RUTAS_SENSIBLES:
        resp, error = safe_request("GET", f"{url_base}/{ruta}", delay=delay, session=session)

        if error:
            resultado["errores"].append(f"{ruta}: {error}")
            continue

        # si directamente da 404 o similar, ni nos molestamos en analizar mas
        if resp.status_code >= 400:
            continue

        huella_ruta = _huella_respuesta(resp)

        es_falso_positivo = False
        if huella_fantasma:
            es_falso_positivo = _parece_falso_positivo(huella_ruta, huella_fantasma)

        contenido_creible = _tiene_contenido_creible(ruta, resp.text or "")

        # decidimos si es un hallazgo real:
        # - si el contenido tiene pistas claras, lo damos por bueno aunque
        #   se parezca un poco a la pagina fantasma (puede ser coincidencia)
        # - si no hay pistas, nos fiamos del filtro de falso positivo
        if contenido_creible is True:
            es_hallazgo = True
        elif es_falso_positivo:
            es_hallazgo = False
        else:
            es_hallazgo = True

        resultado["hallazgos"].append({
            "ruta": ruta,
            "url_probada": f"{url_base}/{ruta}",
            "codigo_http": resp.status_code,
            "tamano_respuesta": huella_ruta["tamano"],
            "expuesto": es_hallazgo,
            "posible_falso_positivo": es_falso_positivo and not contenido_creible,
        })

    resultado["vulnerable"] = any(h["expuesto"] for h in resultado["hallazgos"])

    return resultado


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Uso: python exposed_files.py <url>")
        sys.exit(1)

    salida = ejecutar_plugin(sys.argv[1])
    print(json.dumps(salida, indent=2, ensure_ascii=False))
