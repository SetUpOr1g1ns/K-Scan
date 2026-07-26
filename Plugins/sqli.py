"""
============================================================================
 AVISO ETICO / LEGAL
 Plugin de deteccion de SQL Injection (SQLi).
 Uso EXCLUSIVO en sistemas para los que se tenga autorizacion explicita.
 Este plugin usa unicamente payloads LOGICOS (boolean-based) para
 comparar el comportamiento de la pagina. NO extrae datos reales de
 ninguna base de datos, NO usa UNION SELECT para volcar tablas, NO usa
 tecnicas basadas en tiempo (time-based/SLEEP) que puedan sobrecargar
 el servidor, y NO hace fuerza bruta. Solo observa si la pagina se
 comporta distinto ante una condicion verdadera vs una falsa, lo cual
 ya es suficiente para reportar la vulnerabilidad de forma responsable.
 El rastreo de subpaginas SOLO sigue enlaces <a href> del mismo dominio.
 Prohibido su uso contra sistemas de terceros sin permiso.
============================================================================

Version "escaneo profundo": ahora el plugin hace tres cosas mas, sobre
el mismo enfoque logico/pasivo de siempre:

0. Rastrea el sitio a partir de la URL principal (ej: descubre /login,
   /contacto...) y repite todo el analisis en cada pagina encontrada.

1. Deteccion "clasica" en parametros de la URL, mandando payloads que
   rompen la sintaxis SQL (comillas sueltas, etc) y comparando la
   respuesta contra la pagina normal. Si cambia mucho, sospechoso.

2. Deteccion "logica" (boolean-based), que es mas fiable: mandamos una
   condicion que siempre es verdadera (1=1) y otra que siempre es
   falsa (1=2). Si la pagina responde distinto a cada una, es una señal
   bastante clara de que el input esta llegando crudo a una consulta SQL.
   Ahora la comparacion no es solo por tamano de respuesta, tambien por
   similitud de contenido (mas robusto ante paginas con partes dinamicas
   pequenas, como un reloj o un contador de visitas).

3. Analisis del DOM ampliado: buscamos inputs de texto Y ocultos, dentro
   de <form> o sueltos en cualquier contenedor (div, section, main...),
   con clasificacion semantica por palabras clave del contenedor padre
   (login, busqueda, comentario).
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

from network_utils import safe_request, descubrir_paginas, porcentaje_similitud

# Umbral de similitud para el metodo boolean-based: por debajo de esto
# consideramos que la respuesta cambio "bastante" entre la condicion
# verdadera y la falsa
UMBRAL_SIMILITUD_BOOLEANO = 0.95
PAYLOADS_ROMPE_SINTAXIS = [
    "'",
    "\"",
    "')",
    "';",
]

# Pares (condicion_verdadera, condicion_falsa) para el analisis logico.
# La idea es probar ambos y comparar como responde la pagina a cada uno.
PARES_BOOLEANOS = [
    ("' OR '1'='1", "' OR '1'='2"),
    (" OR 1=1-- -", " OR 1=2-- -"),
    ("1' AND '1'='1", "1' AND '1'='2"),
]

# Mensajes de error tipicos de motores de base de datos, si aparecen
# en la respuesta es una señal bastante fuerte de SQLi
FIRMAS_ERROR_SQL = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.OperationalError",
    "pg_query()",
    "ORA-01756",
    "SQLSTATE",
]

# Palabras clave que buscamos en contenedores padre para saber si un
# input esta dentro de una zona de login, busqueda o comentarios
PALABRAS_CLAVE_CONTENEDOR = {
    "login": ["login", "iniciar sesion", "acceder", "sign in", "usuario", "contraseña"],
    "busqueda": ["buscar", "search", "encuentra", "find"],
    "comentario": ["comentario", "comment", "opina", "deja tu mensaje", "review", "reseña"],
}


def _contiene_firma_error_sql(html):
    """Revisa si el HTML de respuesta trae algun mensaje de error tipico
    de un motor de base de datos."""
    texto = html.lower()
    return any(firma.lower() in texto for firma in FIRMAS_ERROR_SQL)


def probar_parametros_url_sintaxis(url, delay, session=None):
    """Prueba clasica: mandamos comillas sueltas y miramos si aparece
    algun mensaje de error de base de datos en la respuesta."""
    hallazgos = []
    partes = urlparse(url)
    parametros = parse_qs(partes.query)

    if not parametros:
        return hallazgos

    for nombre_param in parametros:
        for payload in PAYLOADS_ROMPE_SINTAXIS:
            nuevos_params = {k: v[0] for k, v in parametros.items()}
            nuevos_params[nombre_param] = nuevos_params[nombre_param] + payload

            url_prueba = urlunparse(partes._replace(query=urlencode(nuevos_params)))
            resp, error = safe_request("GET", url_prueba, delay=delay, session=session)

            if error:
                continue

            if _contiene_firma_error_sql(resp.text):
                hallazgos.append({
                    "punto_entrada": f"parametro URL '{nombre_param}'",
                    "tipo": "error_sql_visible",
                    "payload": payload,
                    "vulnerable": True,
                    "url_probada": url_prueba,
                })
                break  # con encontrar uno para este parametro es suficiente

    return hallazgos


def probar_parametros_url_booleano(url, delay, session=None):
    """Prueba logica (boolean-based): comparamos la respuesta con una
    condicion verdadera contra la respuesta con una condicion falsa.
    Usamos dos senales combinadas: diferencia de tamano Y similitud de
    contenido, para que paginas con partes dinamicas pequenas (reloj,
    contador de visitas) no nos den falsos positivos."""
    hallazgos = []
    partes = urlparse(url)
    parametros = parse_qs(partes.query)

    if not parametros:
        return hallazgos

    for nombre_param in parametros:
        valor_original = parametros[nombre_param][0]

        for condicion_verdadera, condicion_falsa in PARES_BOOLEANOS:
            params_verdadero = {k: v[0] for k, v in parametros.items()}
            params_verdadero[nombre_param] = valor_original + condicion_verdadera
            url_verdadero = urlunparse(partes._replace(query=urlencode(params_verdadero)))

            params_falso = {k: v[0] for k, v in parametros.items()}
            params_falso[nombre_param] = valor_original + condicion_falsa
            url_falso = urlunparse(partes._replace(query=urlencode(params_falso)))

            resp_verdadero, error_v = safe_request("GET", url_verdadero, delay=delay, session=session)
            resp_falso, error_f = safe_request("GET", url_falso, delay=delay, session=session)

            if error_v or error_f:
                continue

            mismo_status = resp_verdadero.status_code == resp_falso.status_code
            diferencia_tamano = abs(len(resp_verdadero.text) - len(resp_falso.text))
            similitud = porcentaje_similitud(resp_verdadero.text, resp_falso.text)

            # dos condiciones alternativas para marcar sospecha, asi no
            # dependemos de un unico umbral que puede fallar segun la web
            cambia_por_tamano = diferencia_tamano > 20
            cambia_por_contenido = similitud < UMBRAL_SIMILITUD_BOOLEANO

            if mismo_status and (cambia_por_tamano or cambia_por_contenido):
                hallazgos.append({
                    "punto_entrada": f"parametro URL '{nombre_param}'",
                    "tipo": "boolean_based",
                    "condicion_verdadera": condicion_verdadera,
                    "condicion_falsa": condicion_falsa,
                    "diferencia_tamano_respuesta": diferencia_tamano,
                    "similitud_contenido": round(similitud, 3),
                    "vulnerable": True,
                })
                break

    return hallazgos


def _texto_contenedor(tag, profundidad=3):
    """Sube por los padres del input (hasta 'profundidad' niveles)
    y junta todo el texto que encuentra, para buscar palabras clave
    tipo 'login', 'buscar', 'comentario' cerca del input."""
    textos = []
    actual = tag
    for _ in range(profundidad):
        if actual is None or actual.name in ("html", "body", None):
            break
        actual = actual.parent
        if actual is not None:
            # get_text con separador para no pegar palabras entre si
            textos.append(actual.get_text(separator=" ", strip=True).lower())
    return " ".join(textos)


def _clasificar_input_por_contenedor(tag):
    """Mira el contenedor padre del input buscando pistas semanticas
    (login, busqueda, comentario) aunque el input no este dentro de
    un <form> tradicional."""
    contexto = _texto_contenedor(tag)
    for categoria, palabras in PALABRAS_CLAVE_CONTENEDOR.items():
        if any(palabra in contexto for palabra in palabras):
            return categoria
    return None


def encontrar_inputs_relevantes(html):
    """A diferencia del plugin de XSS, aqui buscamos TODOS los inputs de
    texto (incluyendo ocultos) de la pagina, esten o no dentro de un
    <form>, porque muchas webs modernas manejan los formularios con JS
    y no usan <form> real. Para cada input, intentamos identificar su
    contenedor semantico."""
    soup = BeautifulSoup(html, "html.parser")
    inputs_encontrados = []

    candidatos = soup.find_all(["input", "textarea"])
    for tag in candidatos:
        tipo = tag.get("type", "text")
        if tag.name == "input" and tipo not in ("text", "search", "email", "hidden", "", None):
            continue

        nombre = tag.get("name") or tag.get("id")
        if not nombre:
            continue  # sin nombre no podemos mandarlo en el submit

        categoria = _clasificar_input_por_contenedor(tag)

        # buscamos el form ancestro mas cercano, si existe
        form_padre = tag.find_parent("form")

        inputs_encontrados.append({
            "nombre": nombre,
            "es_oculto": tipo == "hidden",
            "categoria_detectada": categoria,
            "dentro_de_form": form_padre is not None,
            "accion_form": form_padre.get("action") if form_padre else None,
            "metodo_form": (form_padre.get("method").upper() if form_padre and form_padre.get("method") else "GET"),
        })

    return inputs_encontrados


def probar_inputs_dom(url, html, delay, session=None):
    """Envia los pares boolean-based a cada input relevante encontrado
    en el DOM (dentro o fuera de <form>) y compara las respuestas."""
    hallazgos = []
    inputs = encontrar_inputs_relevantes(html)

    for campo in inputs:
        # si el input no esta en un form no tenemos a donde mandarlo
        # de forma fiable sin ejecutar JS, asi que lo dejamos anotado
        # como punto de entrada a revisar manualmente
        if not campo["dentro_de_form"]:
            hallazgos.append({
                "punto_entrada": f"input '{campo['nombre']}' (sin form, posible JS)",
                "categoria_detectada": campo["categoria_detectada"],
                "tipo": "requiere_revision_manual",
                "vulnerable": False,
                "nota": "Input fuera de <form>, probablemente manejado por JS. Revisar con navegador.",
            })
            continue

        accion = campo["accion_form"] or url
        if accion and not accion.startswith("http"):
            partes = urlparse(url)
            accion = f"{partes.scheme}://{partes.netloc}{accion if accion.startswith('/') else '/' + accion}"

        metodo = campo["metodo_form"]

        for condicion_verdadera, condicion_falsa in PARES_BOOLEANOS[:1]:  # 1 par es suficiente por campo
            datos_verdadero = {campo["nombre"]: condicion_verdadera}
            datos_falso = {campo["nombre"]: condicion_falsa}

            kwargs_v = {"data": datos_verdadero} if metodo == "POST" else {"params": datos_verdadero}
            kwargs_f = {"data": datos_falso} if metodo == "POST" else {"params": datos_falso}

            resp_v, error_v = safe_request(metodo, accion, delay=delay, session=session, **kwargs_v)
            resp_f, error_f = safe_request(metodo, accion, delay=delay, session=session, **kwargs_f)

            if error_v or error_f:
                hallazgos.append({
                    "punto_entrada": f"input '{campo['nombre']}' ({metodo}) -> {accion}",
                    "categoria_detectada": campo["categoria_detectada"],
                    "vulnerable": False,
                    "error": error_v or error_f,
                })
                continue

            hay_error_sql = _contiene_firma_error_sql(resp_v.text) or _contiene_firma_error_sql(resp_f.text)
            diferencia_tamano = abs(len(resp_v.text) - len(resp_f.text))
            cambia_bastante = diferencia_tamano > 20

            es_vulnerable = hay_error_sql or (resp_v.status_code == resp_f.status_code and cambia_bastante)

            hallazgos.append({
                "punto_entrada": f"input '{campo['nombre']}' ({metodo}) -> {accion}",
                "categoria_detectada": campo["categoria_detectada"],
                "tipo": "error_sql_visible" if hay_error_sql else "boolean_based",
                "diferencia_tamano_respuesta": diferencia_tamano,
                "vulnerable": es_vulnerable,
            })

    return hallazgos


def ejecutar_plugin(url, delay=1.0, session=None, profundidad_crawl=1, max_paginas=8):
    """
    Punto de entrada del plugin. Igual patron que headers.py y xss.py.

    Ahora hace un escaneo profundo: descubre subpaginas del mismo
    dominio y repite el analisis (sintaxis + booleano + DOM) en cada una.
    """
    resultado = {
        "plugin": "sqli",
        "url_objetivo": url,
        "paginas_analizadas": [],
        "hallazgos": [],
        "vulnerable": False,
        "errores": [],
    }

    paginas = descubrir_paginas(
        url, session=session, delay=delay,
        profundidad_maxima=profundidad_crawl, max_paginas=max_paginas,
    )
    if not paginas:
        paginas = [url]

    resultado["paginas_analizadas"] = paginas

    for pagina in paginas:
        resp_inicial, error = safe_request("GET", pagina, delay=delay, session=session)
        if error:
            resultado["errores"].append(f"{pagina}: {error}")
            continue

        hallazgos_sintaxis = probar_parametros_url_sintaxis(pagina, delay, session=session)
        hallazgos_booleano_url = probar_parametros_url_booleano(pagina, delay, session=session)
        hallazgos_dom = probar_inputs_dom(pagina, resp_inicial.text, delay, session=session)

        for h in hallazgos_sintaxis + hallazgos_booleano_url + hallazgos_dom:
            h["pagina"] = pagina
            resultado["hallazgos"].append(h)

    resultado["vulnerable"] = any(h.get("vulnerable") for h in resultado["hallazgos"])

    return resultado


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Uso: python sqli.py <url>")
        sys.exit(1)

    salida = ejecutar_plugin(sys.argv[1])
    print(json.dumps(salida, indent=2, ensure_ascii=False))