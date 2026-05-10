"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker

Flujo real (reverse-engineered de captcha.js):
1. time = int(time.time())  [calculado client-side, NO viene del servidor]
2. POST api.php endpoint=question → retorna data.data.question (hash hex del servidor)
3. Web worker hace proof-of-work: busca nonce tal que MD5(question+nonce) empiece con X ceros
4. Envía [{"question": q, "time": t, "nonce": n}] a SIMIT como reCaptchaDTO.response
"""

import os
import time as time_module
import random
import hashlib
import json
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

# ─── Configuración ────────────────────────────────────────────────────────────

SIMIT_URL = "https://consultasimit.fcm.org.co/simit/microservices/estado-cuenta-simit/estadocuenta/consulta"
CAPTCHA_URL = "https://qxcaptcha.fcm.org.co/api.php"

SIMIT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Origin": "https://www.fcm.org.co",
    "Referer": "https://www.fcm.org.co/simit/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "es-CO,es;q=0.9",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
}

CAPTCHA_HEADERS = {
    "Origin": "https://www.fcm.org.co",
    "Referer": "https://www.fcm.org.co/simit/",
    "User-Agent": SIMIT_HEADERS["User-Agent"],
}


# ─── Captcha ──────────────────────────────────────────────────────────────────

async def obtener_question(client: httpx.AsyncClient) -> str | None:
    """
    Llama api.php con endpoint=question (igual que captcha.js).
    Retorna el hash hex que el servidor quiere que el cliente resuelva.
    """
    try:
        # captcha.js usa FormData (multipart), NO application/x-www-form-urlencoded
        r = await client.post(
            CAPTCHA_URL,
            data={"endpoint": "question"},
            headers=CAPTCHA_HEADERS,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            # Retorna data.data.question según captcha.js
            if isinstance(data.get("data"), dict):
                return data["data"].get("question")
            # Algunos servidores retornan data directamente
            if isinstance(data.get("data"), str):
                return data["data"]
    except Exception:
        pass
    return None


def proof_of_work(question: str, captcha_time: int, difficulty: int = 5) -> int:
    """
    Proof-of-work: busca nonce tal que MD5(question + str(nonce))
    empiece con 'difficulty' ceros hexadecimales.

    Basado en el patrón típico de estos sistemas de captcha.
    El captcha-worker.js hace este cómputo en un web worker del browser.
    """
    nonce = 0
    prefix = "0" * difficulty
    while nonce < 10_000_000:
        candidate = hashlib.md5(f"{question}{nonce}".encode()).hexdigest()
        if candidate.startswith(prefix):
            return nonce
        nonce += 1
    # Si no encuentra, retorna un nonce aleatorio (fallback)
    return random.randint(1000000, 9999999)


def construir_captcha_response(question: str, captcha_time: int, difficulty: int = 5) -> str:
    """
    Construye reCaptchaDTO.response igual que el browser.
    Formato: [{"question": <q_del_servidor>, "time": <ts_cliente>, "nonce": <pow_result>}]
    """
    nonce = proof_of_work(question, captcha_time, difficulty)
    captcha_obj = [{"question": question, "time": captcha_time, "nonce": nonce}]
    return json.dumps(captcha_obj, separators=(',', ':'))


# ─── Lógica de consulta SIMIT ─────────────────────────────────────────────────

async def consultar_simit(documento: str) -> dict:
    """
    Consulta SIMIT con cédula o placa.
    Flujo correcto según reverse-engineering de captcha.js:
    1. time = int(time.time())  [client-side]
    2. POST endpoint=question → obtener question del servidor
    3. proof-of-work(question, time) → nonce
    4. POST SIMIT con [{question, time, nonce}]
    """
    documento = documento.strip().upper()
    captcha_time = int(time_module.time())  # igual que Math.floor(Date.now()/1000)

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        # Paso 1: obtener question del servidor qxcaptcha
        question = await obtener_question(client)

        debug_info = {
            "captcha_time": captcha_time,
            "question_obtenida": question,
        }

        if not question:
            # Fallback: usar un hash aleatorio (no funcionará pero da info de debug)
            question = hashlib.md5(str(captcha_time).encode()).hexdigest()
            debug_info["question_fallback"] = True

        # Paso 2: proof-of-work para calcular nonce
        captcha_response = construir_captcha_response(question, captcha_time)
        debug_info["captcha_response_preview"] = captcha_response[:100]

        body = {
            "filtro": documento,
            "reCaptchaDTO": {
                "response": captcha_response,
                "consumidor": "1"
            }
        }

        try:
            response = await client.post(
                SIMIT_URL,
                json=body,
                headers=SIMIT_HEADERS,
                timeout=20
            )

            raw_status = response.status_code
            raw_text = response.text[:500]

            if response.status_code == 200:
                data = response.json()
                return {
                    "exito": True,
                    "datos": data,
                    "documento": documento,
                    "debug": {**debug_info, "status": raw_status}
                }
            else:
                return {
                    "exito": False,
                    "error": f"SIMIT respondió {response.status_code}",
                    "documento": documento,
                    "debug": {
                        **debug_info,
                        "status": raw_status,
                        "body_preview": raw_text,
                    }
                }

        except httpx.ConnectError as e:
            return {
                "exito": False,
                "error": f"No se pudo conectar a SIMIT: {str(e)[:100]}",
                "documento": documento,
                "debug": {**debug_info, "tipo": "ConnectError"}
            }
        except Exception as e:
            return {
                "exito": False,
                "error": f"Error consultando SIMIT: {str(e)[:100]}",
                "documento": documento,
                "debug": {**debug_info, "tipo": type(e).__name__}
            }


def formatear_respuesta(resultado: dict) -> str:
    documento = resultado.get("documento", "")

    if not resultado.get("exito"):
        error = resultado.get("error", "")
        debug = resultado.get("debug", {})
        status = debug.get("status", "?")

        if status == 503:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"El servidor SIMIT está bloqueando la consulta (error 503). "
                f"Sugiero al cliente consultar directamente en fcm.org.co/simit"
            )
        elif status == 401:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"Error de autenticación (captcha inválido, error 401). "
                f"Por favor intenta de nuevo en unos minutos."
            )
        else:
            return (
                f"No pude consultar SIMIT para el documento {documento}. "
                f"El sistema puede estar caído. Intenta de nuevo en unos minutos. "
                f"(Error: {error})"
            )

    datos = resultado.get("datos", {})

    if not datos:
        return f"Cédula {documento}: sin comparendos ni multas registradas en SIMIT. Estado limpio."

    total_comparendos = (
        datos.get("comparendos") or
        datos.get("totalComparendos") or
        datos.get("cantidadComparendos") or
        len(datos.get("listaComparendos", [])) or 0
    )
    total_multas = (
        datos.get("multas") or
        datos.get("totalMultas") or
        datos.get("cantidadMultas") or
        len(datos.get("listaMultas", [])) or 0
    )
    valor_total = (
        datos.get("total") or
        datos.get("valorTotal") or
        datos.get("totalAPagar") or
        datos.get("saldoTotal") or 0
    )

    if valor_total == 0 and total_comparendos == 0 and total_multas == 0:
        return f"Cédula {documento}: sin comparendos ni multas en SIMIT. Estado limpio."

    lineas = [f"Consulta SIMIT - Documento {documento}:"]
    if total_comparendos:
        lineas.append(f"Comparendos: {total_comparendos}")
    if total_multas:
        lineas.append(f"Multas: {total_multas}")
    if valor_total:
        lineas.append(f"Total a pagar: ${int(valor_total):,}")

    lista = datos.get("listaComparendos", datos.get("comparendosList", []))
    if lista:
        lineas.append("Detalle:")
        for item in lista[:5]:
            placa = item.get("placa", item.get("noPlaca", ""))
            estado = item.get("estado", item.get("estadoComparendo", ""))
            valor = item.get("valorAPagar", item.get("valor", 0))
            secretaria = item.get("secretaria", item.get("organismoTransito", ""))
            if placa or estado:
                lineas.append(f"  - Placa {placa} | {secretaria} | {estado} | ${int(valor):,}")

    lineas.append("Movilegal puede ayudarte a gestionar estos comparendos.")
    return "\n".join(lineas)


# ─── Servidor MCP ─────────────────────────────────────────────────────────────

mcp = Server("simit-movilegal")


@mcp.list_tools()
async def listar_herramientas():
    return [
        Tool(
            name="consultar_simit",
            description=(
                "Consulta comparendos, multas e infracciones de tránsito en SIMIT Colombia. "
                "Úsala cuando el cliente proporcione su número de cédula de ciudadanía o la placa "
                "de su vehículo para verificar si tiene multas o comparendos pendientes de pago."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "documento": {
                        "type": "string",
                        "description": (
                            "Número de cédula de ciudadanía o placa del vehículo. "
                            "Ejemplos: '1049615965' o 'KWX584'"
                        )
                    }
                },
                "required": ["documento"]
            }
        )
    ]


@mcp.call_tool()
async def ejecutar_herramienta(name: str, arguments: dict):
    if name != "consultar_simit":
        return [TextContent(type="text", text=f"Herramienta '{name}' no existe en este servidor.")]

    documento = arguments.get("documento", "").strip()
    if not documento:
        return [TextContent(type="text", text="Necesito el número de cédula o placa para hacer la consulta.")]

    resultado = await consultar_simit(documento)
    texto = formatear_respuesta(resultado)
    return [TextContent(type="text", text=texto)]


# ─── App FastAPI ──────────────────────────────────────────────────────────────

app = FastAPI(title="SIMIT MCP - Movilegal")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sse = SseServerTransport("/messages")


@app.get("/sse")
async def endpoint_sse(request: Request):
    async with sse.connect_sse(
        request.scope,
        request.receive,
        request._send
    ) as (leer, escribir):
        await mcp.run(leer, escribir, mcp.create_initialization_options())


@app.post("/messages")
async def endpoint_mensajes(request: Request):
    await sse.handle_post_message(request.scope, request.receive, request._send)


@app.post("/sse")
async def endpoint_sse_post(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=200
        )

    method = body.get("method", "")
    req_id = body.get("id", 1)

    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "simit-movilegal", "version": "3.0"}
            }
        })

    elif method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [{
                    "name": "consultar_simit",
                    "description": (
                        "Consulta comparendos, multas e infracciones de tránsito en SIMIT Colombia."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "documento": {
                                "type": "string",
                                "description": "Número de cédula de ciudadanía o placa del vehículo."
                            }
                        },
                        "required": ["documento"]
                    }
                }]
            }
        })

    elif method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name != "consultar_simit":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32602, "message": f"Herramienta '{tool_name}' no existe."}
            })

        documento = arguments.get("documento", "").strip()
        if not documento:
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": "Necesito el número de cédula o placa."}]}
            })

        resultado = await consultar_simit(documento)
        texto = formatear_respuesta(resultado)

        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": texto}]}
        })

    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})


@app.get("/debug/{documento}")
async def debug_simit(documento: str):
    """Retorna el resultado crudo de SIMIT con debug info del captcha."""
    resultado = await consultar_simit(documento)
    return JSONResponse(resultado)


@app.get("/debug-captcha")
async def debug_captcha():
    """Prueba endpoint=question y otros endpoints de qxcaptcha."""
    resultados = {}
    async with httpx.AsyncClient(timeout=10) as client:
        # El endpoint real según captcha.js es "question"
        tests = [
            ("question-multipart", {"endpoint": "question"}, True),
            ("question-urlencoded", {"endpoint": "question"}, False),
            ("verify-multipart", {"endpoint": "verify"}, True),
            ("verify-urlencoded", {"endpoint": "verify"}, False),
        ]
        for desc, params, multipart in tests:
            try:
                if multipart:
                    r = await client.post(CAPTCHA_URL, data=params, headers=CAPTCHA_HEADERS, timeout=8)
                else:
                    body = "&".join(f"{k}={v}" for k, v in params.items())
                    r = await client.post(
                        CAPTCHA_URL, content=body,
                        headers={**CAPTCHA_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                        timeout=8
                    )
                resultados[desc] = {"status": r.status_code, "body": r.text[:300]}
            except Exception as e:
                resultados[desc] = {"error": str(e)[:100]}
    return JSONResponse(resultados)


@app.get("/debug-captchajs")
async def debug_captcha_js():
    """
    Descarga captcha.js y captcha-worker.js desde qxcaptcha.
    También prueba endpoint=question (el endpoint real del captcha).
    """
    results = {}
    urls = [
        "https://qxcaptcha.fcm.org.co/captcha.js",
        "https://qxcaptcha.fcm.org.co/captcha-worker.js",
        "https://qxcaptcha.fcm.org.co/",
    ]
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        for url in urls:
            try:
                r = await client.get(url, headers=CAPTCHA_HEADERS, timeout=10)
                results[url] = {
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "body": r.text[:10000]
                }
            except Exception as e:
                results[url] = {"error": str(e)[:200]}

        # Probar endpoint=question con FormData (igual que el browser)
        tests = [
            ("question-multipart", {"endpoint": "question"}, True),
            ("question-urlencoded", {"endpoint": "question"}, False),
            ("question-multipart-consumidor", {"endpoint": "question", "consumidor": "1"}, True),
        ]
        for desc, params, multipart in tests:
            try:
                if multipart:
                    r = await client.post(CAPTCHA_URL, data=params, headers=CAPTCHA_HEADERS, timeout=8)
                else:
                    form_body = "&".join(f"{k}={v}" for k, v in params.items())
                    r = await client.post(
                        CAPTCHA_URL, content=form_body,
                        headers={**CAPTCHA_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                        timeout=8
                    )
                results[desc] = {"status": r.status_code, "body": r.text[:500]}
            except Exception as e:
                results[desc] = {"error": str(e)[:100]}

    return JSONResponse(results)


@app.get("/health")
async def health_check():
    return {"status": "ok", "servidor": "SIMIT MCP - Movilegal v3.0"}


@app.get("/")
async def raiz():
    return {
        "nombre": "SIMIT MCP Server - Movilegal",
        "version": "3.0",
        "herramientas": ["consultar_simit"],
        "conectar_en": "/sse",
        "debug": "/debug/{cedula}",
        "debug_captcha": "/debug-captcha",
        "debug_captchajs": "/debug-captchajs"
    }


# ─── Arranque ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
