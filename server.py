"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker — v4.6

Algoritmo de captcha reverse-engineered de captcha-worker.js:
1. time = int(time.time())  [client-side]
2. POST api.php endpoint=question → retorna {datos: {pregunta, dificultad_recomendada}}
3. Para i in range(difficulty):
   - Busca nonce (primo) tal que SHA256(JSON({question,time,nonce})).startswith("0000")
   - verification.append([question, time, nonce])  # ARRAY, no dict
4. Envía verification como reCaptchaDTO.response (array de arrays) a SIMIT

Fixes v4.4:
- API devuelve "datos"/"pregunta"/"dificultad_recomendada" (español), no "data"/"question"
- reCaptchaDTO.response se envía como array real (no string JSON)
- consumidor como integer 1 (no string "1")

Fix v4.5:
- verify_array era dict {"question":..,"time":..,"nonce":..} — debe ser [question, time, nonce]
  (JS hace: verification.push([question, time, nonce]) — array de arrays)
"""

import os
import time as time_module
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


# ─── Captcha (algoritmo real de captcha-worker.js) ────────────────────────────

def es_primo(n: int) -> bool:
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def resolver_captcha(question: str, captcha_time: int, nonce_inicial: int = 1) -> dict:
    prefijo = f'{{"question":"{question}","time":{captcha_time},"nonce":'.encode()
    sufijo = b'}'
    nonce = nonce_inicial + 1
    while True:
        data = prefijo + str(nonce).encode() + sufijo
        hash_actual = hashlib.sha256(data).hexdigest()
        if hash_actual[:4] == "0000" and es_primo(nonce):
            return {
                "verify_array": [question, captcha_time, nonce],
                "nonce": nonce,
                "hash": hash_actual,
            }
        nonce += 1


async def obtener_question(client: httpx.AsyncClient) -> dict:
    try:
        r = await client.post(
            CAPTCHA_URL, data={"endpoint": "question"},
            headers=CAPTCHA_HEADERS, timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            datos = data.get("datos") or data.get("data")
            if not data.get("error") and isinstance(datos, dict):
                resultado = {
                    "question": datos.get("pregunta") or datos.get("question"),
                    "recommended_difficulty": datos.get("dificultad_recomendada") or datos.get("recommended_difficulty", 2),
                }
                resultado["_headers"] = dict(r.headers)
                resultado["_cookies"] = dict(r.cookies)
                return resultado
    except Exception:
        pass
    return {}


def construir_captcha_response(question: str, captcha_time: int, difficulty: int) -> list:
    verification = []
    nonce = 1
    for _ in range(difficulty):
        resultado = resolver_captcha(question, captcha_time, nonce)
        nonce = resultado["nonce"]
        verification.append(resultado["verify_array"])
    return verification


# ─── Lógica de consulta SIMIT ────────────────────────────────────────────────

async def prefetch_session_cookies(client: httpx.AsyncClient) -> dict:
    """
    Fix v4.6: Visita fcm.org.co/simit/ antes de la consulta para obtener
    cookies de sesión reales (igual que un browser al cargar la página).
    SIMIT puede requerir estas cookies además de las del captcha.
    """
    session_cookies = {}
    try:
        r = await client.get(
            "https://www.fcm.org.co/simit/",
            headers={
                "User-Agent": SIMIT_HEADERS["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "es-CO,es;q=0.9",
            },
            timeout=10,
        )
        session_cookies.update(dict(r.cookies))
    except Exception:
        pass
    return session_cookies


async def consultar_simit(documento: str) -> dict:
    documento = documento.strip().upper()
    captcha_time = int(time_module.time())

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        # Paso 0 (v4.6): pre-fetch cookies de sesión del sitio principal
        session_cookies = await prefetch_session_cookies(client)

        # Paso 1: obtener question del servidor captcha
        captcha_data = await obtener_question(client)
        question = captcha_data.get("question")
        difficulty = captcha_data.get("recommended_difficulty", 2)

        debug_info = {
            "captcha_time": captcha_time,
            "question": question,
            "difficulty": difficulty,
            "captcha_cookies": captcha_data.get("_cookies", {}),
            "session_cookies": session_cookies,
        }

        if not question:
            return {
                "exito": False,
                "error": "No se pudo obtener question del captcha",
                "documento": documento,
                "debug": debug_info,
            }

        try:
            pow_array = construir_captcha_response(question, captcha_time, difficulty)
            debug_info["captcha_response"] = str(pow_array)[:200]
        except Exception as e:
            return {
                "exito": False,
                "error": f"Error en proof-of-work: {str(e)[:100]}",
                "documento": documento,
                "debug": debug_info,
            }

        body = {
            "filtro": documento,
            "reCaptchaDTO": {
                "response": pow_array,
                "consumidor": 1,
            },
        }

        # Combinar cookies: sesión principal + captcha ADC
        captcha_cookies = captcha_data.get("_cookies", {})
        todas_cookies = {**session_cookies, **captcha_cookies}
        cookie_str = "; ".join(f"{k}={v}" for k, v in todas_cookies.items())
        simit_headers_req = {**SIMIT_HEADERS}
        if cookie_str:
            simit_headers_req["Cookie"] = cookie_str
        debug_info["cookie_enviada_a_simit"] = cookie_str[:150] if cookie_str else "ninguna"

        try:
            response = await client.post(
                SIMIT_URL, json=body, headers=simit_headers_req, timeout=20,
            )
            raw_status = response.status_code
            raw_text = response.text[:1000]
            simit_headers = dict(response.headers)
            if response.status_code == 200:
                return {
                    "exito": True,
                    "datos": response.json(),
                    "documento": documento,
                    "debug": {**debug_info, "status": raw_status},
                }
            else:
                return {
                    "exito": False,
                    "error": f"SIMIT respondió {response.status_code}",
                    "documento": documento,
                    "debug": {**debug_info, "status": raw_status, "body_preview": raw_text, "simit_response_headers": simit_headers},
                }
        except httpx.ConnectError as e:
            return {"exito": False, "error": f"No se pudo conectar a SIMIT: {str(e)[:100]}", "documento": documento, "debug": {**debug_info, "tipo": "ConnectError"}}
        except Exception as e:
            return {"exito": False, "error": f"Error consultando SIMIT: {str(e)[:100]}", "documento": documento, "debug": {**debug_info, "tipo": type(e).__name__}}


def formatear_respuesta(resultado: dict) -> str:
    documento = resultado.get("documento", "")
    if not resultado.get("exito"):
        error = resultado.get("error", "")
        status = resultado.get("debug", {}).get("status", "?")
        if status == 401:
            return f"No pude consultar SIMIT para {documento}. Captcha rechazado (error 401). Intenta de nuevo."
        elif status == 503:
            return f"No pude consultar SIMIT para {documento}. Servidor caído (503). Consulta en fcm.org.co/simit"
        else:
            return f"No pude consultar SIMIT para {documento}. Intenta de nuevo. (Error: {error})"
    datos = resultado.get("datos", {})
    if not datos:
        return f"Cédula {documento}: sin comparendos ni multas. Estado limpio."
    total_comparendos = datos.get("comparendos") or datos.get("totalComparendos") or len(datos.get("listaComparendos", [])) or 0
    valor_total = datos.get("total") or datos.get("valorTotal") or datos.get("totalAPagar") or 0
    if valor_total == 0 and total_comparendos == 0:
        return f"Cédula {documento}: sin comparendos ni multas. Estado limpio."
    lineas = [f"Consulta SIMIT - Documento {documento}:"]
    if total_comparendos:
        lineas.append(f"Comparendos: {total_comparendos}")
    if valor_total:
        lineas.append(f"Total a pagar: ${int(valor_total):,}")
    lista = datos.get("listaComparendos", [])
    for item in lista[:5]:
        placa = item.get("placa", item.get("noPlaca", ""))
        estado = item.get("estado", "")
        valor = item.get("valorAPagar", item.get("valor", 0))
        if placa or estado:
            lineas.append(f"  - Placa {placa} | {estado} | ${int(valor):,}")
    lineas.append("Movilegal puede ayudarte a gestionar estos comparendos.")
    return "\n".join(lineas)


# ─── Servidor MCP ───────────────────────────────────────────────────

mcp = Server("simit-movilegal")


@mcp.list_tools()
async def listar_herramientas():
    return [Tool(name="consultar_simit", description="Consulta comparendos, multas e infracciones de tránsito en SIMIT Colombia. Usala cuando el cliente de su cédula o placa.", inputSchema={"type": "object", "properties": {"documento": {"type": "string", "description": "Cédula o placa."}}, "required": ["documento"]})]


@mcp.call_tool()
async def ejecutar_herramienta(name: str, arguments: dict):
    if name != "consultar_simit":
        return [TextContent(type="text", text=f"Herramienta '{name}' no existe.")]
    documento = arguments.get("documento", "").strip()
    if not documento:
        return [TextContent(type="text", text="Necesito el número de cédula o placa.")]
    resultado = await consultar_simit(documento)
    return [TextContent(type="text", text=formatear_respuesta(resultado))]


# ─── App FastAPI ──────────────────────────────────────────────────────────────

app = FastAPI(title="SIMIT MCP - Movilegal")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
sse = SseServerTransport("/messages")


@app.get("/sse")
async def endpoint_sse(request: Request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as (leer, escribir):
        await mcp.run(leer, escribir, mcp.create_initialization_options())


@app.post("/messages")
async def endpoint_mensajes(request: Request):
    await sse.handle_post_message(request.scope, request.receive, request._send)


@app.post("/sse")
async def endpoint_sse_post(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=200)
    method = body.get("method", "")
    req_id = body.get("id", 1)
    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "simit-movilegal", "version": "4.6"}}})
    elif method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{"name": "consultar_simit", "description": "Consulta comparendos y multas en SIMIT Colombia.", "inputSchema": {"type": "object", "properties": {"documento": {"type": "string", "description": "Cédula o placa."}}, "required": ["documento"]}}]}})
    elif method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        if tool_name != "consultar_simit":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Herramienta '{tool_name}' no existe."}})
        documento = arguments.get("documento", "").strip()
        if not documento:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "Necesito cédula o placa."}]}})
        resultado = await consultar_simit(documento)
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": formatear_respuesta(resultado)}]}})
    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})


@app.get("/debug-captcha")
async def debug_captcha():
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            r = await client.post(CAPTCHA_URL, data={"endpoint": "question"}, headers=CAPTCHA_HEADERS, timeout=10)
            body_data = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
            return JSONResponse({"status_code": r.status_code, "cookies": dict(r.cookies), "body": body_data})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/debug/{documento}")
async def debug_simit(documento: str):
    return JSONResponse(await consultar_simit(documento))


@app.get("/health")
async def health_check():
    return {"status": "ok", "servidor": "SIMIT MAP - Movilegal v4.6"}


@app.get("/")
async def raiz():
    return {"nombre": "SIMIT MCP Server - Movilegal", "version": "4.6", "debug": "/debug/{cedula}"}


# ─── Arranque ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
