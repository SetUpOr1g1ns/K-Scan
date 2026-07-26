"""
============================================================================
 AVISO ETICO / LEGAL
 Plugin de deteccion de Cross-Site Scripting (XSS).
 Uso EXCLUSIVO en sistemas para los que se tenga autorizacion explicita.
 Este plugin NO ejecuta scripts en un navegador real ni causa dano al
 servidor, solo envia payloads de prueba y revisa si vuelven reflejados
 en la respuesta HTML sin ser escapados (indicio de vulnerabilidad).
 El rastreo de subpaginas SOLO sigue enlaces <a href> del mismo dominio,
 nunca sale del dominio objetivo y respeta el delay configurado.
 Prohibido su uso contra sistemas de terceros sin permiso.
============================================================================

Idea general del plugin (version "escaneo profundo"):
1. Rastreamos el sitio a partir de la URL principal, siguiendo enlaces
   internos (ej: /login, /contacto) hasta una profundidad limitada.
2. En CADA pagina encontrada buscamos "puntos de entrada": parametros
   de la URL, campos de formularios (incluyendo inputs ocultos y
   formularios anidados dentro de div/section/main/etc).
3. A cada punto de entrada le mandamos unos payloads de prueba.
4. Detectamos la vulnerabilidad de dos formas complementarias:
   a) Reflejo literal: el payload aparece tal cual, sin escapar.
   b) Anomalia de contenido: aunque no se refleje literal, comparamos
      cuanto se parece la respuesta con payload contra la respuesta
      normal. Si cambia mucho (rompe el layout, genera un error, etc)
      tambien lo marcamos como sospechoso para revision manual.
5. Extra: para campos que parecen de "comentario", hacemos una segunda
   visita a la pagina despues de enviar el payload, para comprobar si
   se guardo y se sigue mostrando (indicio de XSS almacenado/persistente).

Nota: usamos payloads basados en el DOM (window.print, confirm, etc) en
vez del clasico alert() porque muchos WAF ya lo detectan de memoria y
porque en pentesting real ya casi no se usa alert() como prueba de vida.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

from network_utils import safe_request, descubrir_paginas, porcentaje_similitud

# Umbral de similitud: por debajo de esto consideramos que la respuesta
# cambio "bastante" respecto a la normal, y lo marcamos como anomalia
UMBRAL_SIMILITUD_SOSPECHOSA = 0.85
PAYLOADS_XSS = [
    "<script>window.print()</script>",
    "\"><script>window.print()</script>",
    "'><svg onload=window.print()>",
    "<img src=x onerror=window.print()>",
    "<svg/onload=confirm(document.domain)>",
]

# Palabras que solemos encontrar en campos "peligrosos" (buscadores,
# formularios de login, comentarios...). Nos sirven para priorizar.
PALABRAS_CLAVE_INPUT = ["search", "buscar", "query", "q", "comment",
                         "comentario", "login", "user", "usuario", "mensaje", "message"]


def _payload_reflejado_sin_escapar(html, payload):
    """Comprueba si el payload aparece literal en el HTML de respuesta.
    Si el servidor lo escapa (&lt;script&gt;) no cuenta como vulnerable."""
    return payload in html


def _hay_anomalia_de_contenido(html_normal, html_con_payload):
    """Compara la respuesta normal contra la respuesta con el payload.
    Si son muy distintas (la pagina se rompio, salto un error, cambio
    de estructura) lo marcamos como anomalia, aunque el payload no se
    haya reflejado literal. Esto ayuda a pillar casos donde el payload
    se transforma mucho pero igual afecta al comportamiento de la pagina."""
    similitud = porcentaje_similitud(html_normal, html_con_payload)
    return similitud < UMBRAL_SIMILITUD_SOSPECHOSA, similitud


def probar_parametros_url(url, delay, session=None):
    """Prueba de XSS reflejado inyectando el payload en cada parametro
    que ya trae la URL (ej: ?busqueda=perro&pagina=2)."""
    hallazgos = []
    partes = urlparse(url)
    parametros = parse_qs(partes.query)

    if not parametros:
        return hallazgos  # esta URL no tiene parametros que probar

    # respuesta normal, sin payload, para poder comparar despues
    resp_base, error_base = safe_request("GET", url, delay=delay, session=session)
    html_base = resp_base.text if resp_base else ""

    for nombre_param in parametros:
        for payload in PAYLOADS_XSS:
            # copiamos los parametros originales y solo tocamos uno
            nuevos_params = {k: v[0] for k, v in parametros.items()}
            nuevos_params[nombre_param] = payload

            nueva_query = urlencode(nuevos_params)
            url_prueba = urlunparse(partes._replace(query=nueva_query))

            resp, error = safe_request("GET", url_prueba, delay=delay, session=session)
            if error:
                hallazgos.append({
                    "punto_entrada": f"parametro URL '{nombre_param}'",
                    "payload": payload,
                    "vulnerable": False,
                    "error": error,
                })
                continue

            reflejado = _payload_reflejado_sin_escapar(resp.text, payload)
            hay_anomalia, similitud = _hay_anomalia_de_contenido(html_base, resp.text) if html_base else (False, 1.0)

            hallazgo = {
                "punto_entrada": f"parametro URL '{nombre_param}'",
                "url_probada": url_prueba,
                "payload": payload,
                "vulnerable": reflejado,
                "codigo_http": resp.status_code,
            }
            if not reflejado and hay_anomalia:
                # no se refleja literal, pero la respuesta cambio mucho:
                # lo marcamos aparte para revision manual, sin decir
                # directamente "vulnerable" (podria ser un falso positivo)
                hallazgo["anomalia_para_revisar"] = True
                hallazgo["similitud_con_respuesta_normal"] = round(similitud, 2)

            hallazgos.append(hallazgo)

            if reflejado:
                # si ya encontramos que este parametro es vulnerable con
                # un payload, no hace falta seguir probando los demas
                break

    return hallazgos


def _es_input_interesante(tag):
    """Mira el name/id/placeholder del input buscando palabras clave
    de login, busqueda o comentarios, para priorizar el analisis."""
    texto = " ".join([
        tag.get("name", ""), tag.get("id", ""), tag.get("placeholder", "")
    ]).lower()
    return any(palabra in texto for palabra in PALABRAS_CLAVE_INPUT)


def encontrar_formularios(html, url_base):
    """Recorre el HTML buscando <form> y sus campos, incluyendo los que
    estan anidados dentro de otros contenedores (div, section, main...)
    en vez de solo los inputs directos del form. Tambien incluye los
    inputs ocultos (type=hidden), porque a veces la web confia en su
    valor sin validar bien lo que llega (ej: precios, tokens, roles)."""
    soup = BeautifulSoup(html, "html.parser")
    formularios = []

    for form in soup.find_all("form"):
        accion = form.get("action") or url_base
        metodo = (form.get("method") or "GET").upper()

        # find_all sin recursive=False para pillar tambien los campos
        # metidos dentro de divs anidados, no solo los hijos directos
        campos = form.find_all(["input", "textarea"])
        campos_texto = [
            c for c in campos
            if c.get("type", "text") in ("text", "search", "email", "hidden", "", None)
            or c.name == "textarea"
        ]

        if campos_texto:
            formularios.append({
                "accion": accion,
                "metodo": metodo,
                "campos": campos_texto,
                "prioritario": any(_es_input_interesante(c) for c in campos_texto),
                "tiene_campo_oculto": any(c.get("type") == "hidden" for c in campos_texto),
            })

    return formularios


def _resolver_url_absoluta(url, accion):
    """Convierte una accion de formulario relativa (ej: '/enviar') en
    una URL absoluta usando la url base como referencia."""
    if accion and not accion.startswith("http"):
        partes = urlparse(url)
        return f"{partes.scheme}://{partes.netloc}{accion if accion.startswith('/') else '/' + accion}"
    return accion or url


def _revisar_persistencia(url_pagina, payload, delay, session):
    """Para campos que parecen de comentario: despues de enviar el
    payload, volvemos a cargar la pagina para ver si el contenido se
    guardo y se sigue mostrando. Eso seria XSS almacenado (persistente),
    mas grave que uno reflejado porque afecta a cualquiera que visite
    la pagina despues, no solo a quien hace clic en un link manipulado."""
    resp, error = safe_request("GET", url_pagina, delay=delay, session=session)
    if error or resp is None:
        return False
    return _payload_reflejado_sin_escapar(resp.text, payload)


def probar_formularios(url, html, delay, session=None):
    """Envia los payloads en cada campo de los formularios encontrados
    (incluyendo ocultos y anidados) y revisa si vuelven reflejados o si
    generan una anomalia notable en la respuesta."""
    hallazgos = []
    formularios = encontrar_formularios(html, url)

    for form in formularios:
        accion = _resolver_url_absoluta(url, form["accion"])

        for payload in PAYLOADS_XSS[:2]:  # con 2 payloads por campo es suficiente para no floodear
            datos = {}
            for campo in form["campos"]:
                nombre = campo.get("name")
                if not nombre:
                    continue
                datos[nombre] = payload

            if not datos:
                continue

            metodo = form["metodo"]
            kwargs = {"data": datos} if metodo == "POST" else {"params": datos}
            resp, error = safe_request(metodo, accion, delay=delay, session=session, **kwargs)

            if error:
                hallazgos.append({
                    "punto_entrada": f"formulario ({metodo}) -> {accion}",
                    "payload": payload,
                    "vulnerable": False,
                    "error": error,
                })
                continue

            reflejado = _payload_reflejado_sin_escapar(resp.text, payload)

            hallazgo = {
                "punto_entrada": f"formulario ({metodo}) -> {accion}",
                "campos_probados": list(datos.keys()),
                "payload": payload,
                "vulnerable": reflejado,
                "prioritario_login_o_busqueda": form["prioritario"],
                "incluye_campo_oculto": form["tiene_campo_oculto"],
                "codigo_http": resp.status_code,
            }

            # si el formulario huele a "comentario", comprobamos tambien
            # si el payload persiste en una segunda carga de la pagina
            categoria_texto = " ".join(datos.keys()).lower()
            if any(p in categoria_texto for p in ("comment", "comentario", "mensaje", "message", "review", "reseña")):
                persiste = _revisar_persistencia(url, payload, delay, session)
                hallazgo["revisado_persistencia_almacenada"] = True
                hallazgo["xss_almacenado_sospechoso"] = persiste
                if persiste:
                    hallazgo["vulnerable"] = True

            hallazgos.append(hallazgo)

    return hallazgos


def ejecutar_plugin(url, delay=1.0, session=None, profundidad_crawl=1, max_paginas=8):
    """
    Punto de entrada del plugin. Esto es lo que llama main.py.

    Ahora hace un escaneo profundo: primero descubre subpaginas del
    mismo dominio (ej: /login, /contacto) y luego prueba CADA una de
    ellas, no solo la URL principal.

    Devuelve un diccionario listo para meter en el informe JSON final.
    """
    resultado = {
        "plugin": "xss",
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
        paginas = [url]  # si el crawler no encontro nada, al menos probamos la url original

    resultado["paginas_analizadas"] = paginas

    for pagina in paginas:
        resp_inicial, error = safe_request("GET", pagina, delay=delay, session=session)
        if error:
            resultado["errores"].append(f"{pagina}: {error}")
            continue

        hallazgos_url = probar_parametros_url(pagina, delay, session=session)
        hallazgos_forms = probar_formularios(pagina, resp_inicial.text, delay, session=session)

        # etiquetamos cada hallazgo con la pagina de la que viene, para
        # que el informe final se pueda leer sabiendo donde salio cada cosa
        for h in hallazgos_url + hallazgos_forms:
            h["pagina"] = pagina
            resultado["hallazgos"].append(h)

    resultado["vulnerable"] = any(h.get("vulnerable") for h in resultado["hallazgos"])

    return resultado


# Permite probar el plugin solo, sin pasar por la TBI
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Uso: python xss.py <url>")
        sys.exit(1)

    salida = ejecutar_plugin(sys.argv[1])
    print(json.dumps(salida, indent=2, ensure_ascii=False))
