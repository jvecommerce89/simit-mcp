"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker

Flujo real:
1. Llama qxcaptcha.fcm.org.co/api.php para obtener el token de sesión (time)
2. Construye el body con reCaptchaDTO según el formato real del browser
3. POST a consultasimit.fcm.org.co con filtro + reCaptchaDTO
"""

import os
import time
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

# Headers idénticos a los que envía el browser real
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


# ─── Captcha ──────────────────────────────────────────────────────────────────

async def obtener_token_captcha(client: httpx.AsyncClient) -> dict | None:
    endpoints = ["init", "generate", "token", "challenge", "start", "create"]
    headers_captcha = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://www.fcm.org.co",
        "Referer": "https://www.fcm.org.co/simit/",
        "User-Agent": SIMIT_HEADERS["User-Agent"],
    }

    for ep in endpoints:
        try:
            r = await client.post(
                CAPTCHA_URL,
                content=f"consumidor=1&endpoint={ep}",
                headers=headers_captcha,
                timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("error") != "MISSING_ENDPOINT" and data.get("data") is not False:
                    return {"endpoint": ep, "data": data, "time": data.get("time") or data.get("timestamp")}
        except Exception:
            continue

    return {"endpoint": "fallback", "data": None, "time": int(time.time())}


def construir_captcha_response(captcha_time: int, seed: str = None) -> str:
    nonce = random.randint(1000000, 9999999)
    if seed:
        question = hashlib.md5(f"{seed}{nonce}".encode()).hexdigest()
    else:
        question = hashlib.md5(f"{captcha_time}{nonce}".encode()).hexdigest()
    captcha_obj = [{"question": question, "time": captcha_time, "nonce": nonce}]
    return json.dumps(captcha_obj, separators=(',', ':'))


# ─── Lógica de consulta SIMIT ─────────────────────────────────────────────────

async def consultar_simit(documento: str) -> dict:
    documento = documento.strip().upper()

    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        captcha_info = await obtener_token_captcha(client)
        captcha_time = captcha_info.get("time") or int(time.time())
        seed = captcha_info.get("data", {}) or {}
        seed_str = seed.get("seed") or seed.get("challenge") or seed.get("token") or None

        captcha_response = construir_captcha_response(captcha_time, seed_str)

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
                    "debug": {"status": raw_status, "captcha_time": captcha_time}
                }
            else:
                return {
                    "exito": False,
                    "error": f"SIMIT respondió {response.status_code}",
                    "documento": documento,
                    "debug": {
                        "status": raw_status,
                        "body_preview": raw_text,
                        "captcha_time": captcha_time,
                        "captcha_endpoint": captcha_info.get("endpoint")
                    }
                }

        except httpx.ConnectError as e:
            return {
                "exito": False,
                "error": f"No se pudo conectar a SIMIT: {str(e)[:100]}",
                "documento": documento,
                "debug": {"tipo": "ConnectError"}
            }
        except Exception as e:
            return {
                "exito": False,
                "error": f"Error consultando SIMIT: {str(e)[:100]}",
                "documento": documento,
                "debug": {"tipo": type(e).__name__}
            }


def formatear_respuesta(resultado: dict) -> str:
    documento = resultado.get("documento", "")

    if not resultado.get("exito"):
        debug = resultado.get("debug", {})
        status = debug.get("status", "?")
        error = resultado.get("error", "")

        if status == 503:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"El servidor SIMIT está bloqueando la consulta (error 503 - geoblock por IP). "
                f"Sugiero al cliente consultar directamente en fcm.org.co/simit"
            )
        elif status == 401:
            return (
                f"No pude consultar SIMIT para {documento}. "
                f"Error de autenticación (error 401). Intenta de nuevo en unos minutos."
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
                        "description": "Número de cédula de ciudadanía o placa del vehículo."
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


# ─── App FastAPI + SSE Transport ──────────────────────────────────────────────

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
                "serverInfo": {"name": "simit-movilegal", "version": "2.0"}
            }
        })

    elif method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [{
                    "name": "consultar_simit",
                    "description": (
                        "Consulta comparendos, multas e infracciones de tránsito en SIMIT Colombia. "
                        "Úsala cuando el cliente proporcione su número de cédula de ciudadanía o la placa "
                        "de su vehículo para verificar si tiene multas o comparendos pendientes de pago."
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
    resultado = await consultar_simit(documento)
    return JSONResponse(resultado)


@app.get("/debug-captcha")
async def debug_captcha():
    resultados = {}
    async with httpx.AsyncClient(timeout=10) as client:
        endpoints = ["init", "generate", "token", "challenge", "start", "create", "validate", "verify"]
        for ep in endpoints:
            try:
                r = await client.post(
                    CAPTCHA_URL,
                    content=f"consumidor=1&endpoint={ep}",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://www.fcm.org.co",
                        "Referer": "https://www.fcm.org.co/simit/",
                    },
                    timeout=5
                )
                resultados[ep] = {"status": r.status_code, "body": r.text[:200]}
            except Exception as e:
                resultados[ep] = {"error": str(e)[:100]}
    return JSONResponse(resultados)


@app.get("/health")
async def health_check():
    return {"status": "ok", "servidor": "SIMIT MCP - Movilegal v2.0"}


@app.get("/")
async def raiz():
    return {
        "nombre": "SIMIT MCP Server - Movilegal",
        "version": "2.0",
        "herramientas": ["consultar_simit"],
        "conectar_en": "/sse",
        "debug": "/debug/{cedula}",
        "debug_captcha": "/debug-captcha"
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
