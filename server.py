"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker — v4.1

Algoritmo de captcha reverse-engineered de captcha-worker.js:
1. time = int(time.time())  [client-side]
2. POST api.php endpoint=question → retorna {question, recommended_difficulty}
3. Para i in range(difficulty):
   - Busca nonce (primo) tal que SHA256(JSON({question,time,nonce})).startswith("0000")
   - verification.append({question, time, nonce})
4. Envía verification como reCaptchaDTO.response a SIMIT

Optimización v4.1: prefijo pre-formateado en bytes para PoW 4x más rápido (~3s vs 13s)
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
    """
    Mismo resultado que isPrime() del captcha-worker.js pero O(sqrt(n)) en vez de O(n).
    El JS usa for(i=2; i<n; i++) — da los mismos primos, solo es más lento.
    """
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
    """
    Implementación exacta de solveCaptcha() del captcha-worker.js:

    while sha256(JSON({question, time, nonce})).substr(0,4) != "0000" OR !isPrime(nonce):
        nonce++

    Optimización: pre-formatear el prefijo constante (question+time) una sola vez
    para evitar el overhead de json.dumps en cada iteración (~4x más rápido).
    """
    # Pre-formatear el prefijo que no cambia entre iteraciones
    # JSON.stringify de JS produce exactamente: {"question":"...","time":...,"nonce":N}
    prefijo = f'{{"question":"{question}","time":{captcha_time},"nonce":'.encode()
    sufijo = b'}'

    nonce = nonce_inicial + 1  # worker empieza en 1 y hace nonce++ inmediatamente
    while True:
        data = prefijo + str(nonce).encode() + sufijo
        hash_actual = hashlib.sha256(data).hexdigest()

        if hash_actual[:4] == "0000" and es_primo(nonce):
            verify_obj = {"question": question, "time": captcha_time, "nonce": nonce}
            return {
                "verify_array": verify_obj,
                "nonce": nonce,
                "hash": hash_actual
            }
        nonce += 1


async def obtener_question(client: httpx.AsyncClient) -> dict:
    """
    Llama api.php con endpoint=question (FormData, igual que captcha.js).
    Retorna {question, recommended_difficulty} o None si falla.
    """
    try:
        r = await client.post(
            CAPTCHA_URL,
            data={"endpoint": "question"},
            headers=CAPTCHA_HEADERS,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if not data.get("error") and isinstance(data.get("data"), dict):
                return data["data"]  # {question, recommended_difficulty}
    except Exception:
        pass
    return {}


def construir_captcha_response(question: str, captcha_time: int, difficulty: int) -> str:
    """
    Implementación exacta del loop del captcha-worker.js:

    var verification = []
    for(var i=0; i < times; i++) {
        var response = solveCaptcha(data, nonce);
        nonce = response.nonce;
        verification.push(response.verify_array);
    }
    """
    verification = []
    nonce = 1  # nonce inicial del worker
    for _ in range(difficulty):
        resultado = resolver_captcha(question, captcha_time, nonce)
        nonce = resultado["nonce"]  # el próximo ciclo empieza desde este nonce
        verification.append(resultado["verify_array"])
    return json.dumps(verification, separators=(',', ':'))


# ─── Lógica de consulta SIMIT ─────────────────────────────────────────────────

async def consultar_simit(documento: str) -> dict:
    documento = documento.strip().upper()
    captcha_time = int(time_module.time())  # Math.floor(Date.now()/1000)

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        # Paso 1: obtener question del servidor
        captcha_data = await obtener_question(client)
        question = captcha_data.get("question")
        difficulty = captcha_data.get("recommended_difficulty", 2)

        debug_info = {
            "captcha_time": captcha_time,
            "question": question,
            "difficulty": difficulty,
        }

        if not question:
            return {
                "exito": False,
                "error": "No se pudo obtener question del captcha",
                "documento": documento,
                "debug": debug_info
            }

        # Paso 2: proof-of-work con SHA256
        try:
            captcha_response = construir_captcha_response(question, captcha_time, difficulty)
            debug_info["captcha_response"] = captcha_response[:200]
        except Exception as e:
            return {
                "exito": False,
                "error": f"Error en proof-of-work: {str(e)[:100]}",
                "documento": documento,
                "debug": debug_info
            }

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

        if status == 401:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"Error de autenticación (captcha rechazado, error 401). "
                f"Por favor intenta de nuevo."
            )
        elif status == 503:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"Servidor SIMIT caído (error 503). "
                f"Consulta directamente en fcm.org.co/simit"
            )
        else:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"Intenta de nuevo en unos minutos. (Error: {error})"
            )

    datos = resultado.get("datos", {})

    if not datos:
        return f"Cédula {documento}: sin comparendos ni multas en SIMIT. Estado limpio."

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


# ─── Servidor MCP ────────────────────────────────────────────────────────────

mcp = Server("simit-movilegal")


@mcp.list_tools()
async def listar_herramientas():
    return [
        Tool(
            name="consultar_simit",
            description=(
                "Consulta comparendos, multas e infracciones de tránsito en SIMIT Colombia. "
                "Úsala cuando el cliente proporcione su cédula de ciudadanía o placa del vehículo."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "documento": {
                        "type": "string",
                        "description": "Número de cédula o placa. Ejemplos: '1049615965' o 'KWX584'"
                    }
                },
                "required": ["documento"]
            }
        )
    ]


@mcp.call_tool()
async def ejecutar_herramienta(name: str, arguments: dict):
    if name != "consultar_simit":
        return [TextContent(type="text", text=f"Herramienta '{name}' no existe.")]

    documento = arguments.get("documento", "").strip()
    if not documento:
        return [TextContent(type="text", text="Necesito el número de cédula o placa.")]

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
                "serverInfo": {"name": "simit-movilegal", "version": "4.1"}
            }
        })

    elif method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [{
                    "name": "consultar_simit",
                    "description": "Consulta comparendos y multas en SIMIT Colombia.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "documento": {"type": "string", "description": "Cédula o placa."}
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
                "result": {"content": [{"type": "text", "text": "Necesito cédula o placa."}]}
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
    """Debug endpoint — resultado crudo con info del captcha."""
    resultado = await consultar_simit(documento)
    return JSONResponse(resultado)


@app.get("/health")
async def health_check():
    return {"status": "ok", "servidor": "SIMIT MCP - Movilegal v4.1"}


@app.get("/")
async def raiz():
    return {
        "nombre": "SIMIT MCP Server - Movilegal",
        "version": "4.1",
        "algoritmo": "SHA256 + isPrime proof-of-work optimizado (4x más rápido)",
        "herramientas": ["consultar_simit"],
        "conectar_en": "/sse",
        "debug": "/debug/{cedula}",
    }


# ─── Arranque ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
