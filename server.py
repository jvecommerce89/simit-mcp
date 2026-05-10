"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker

Este servidor expone la herramienta consultar_simit que Luisa usa
automáticamente cuando un cliente le da su cédula o placa.
"""

import os
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

SIMIT_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://www.fcm.org.co",
    "Referer": "https://www.fcm.org.co/simit/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "es-CO,es;q=0.9,es-419;q=0.8",
}

FORMATOS_BODY = [
    lambda doc: {"noIdentificacion": doc},
    lambda doc: {"numeroDocumento": doc},
    lambda doc: {"identificacion": doc},
    lambda doc: {"cedula": doc},
    lambda doc: {"documento": doc},
]


# ─── Lógica de consulta SIMIT ─────────────────────────────────────────────────

async def consultar_simit(documento: str) -> dict:
    documento = documento.strip().upper()
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        for formato in FORMATOS_BODY:
            body = formato(documento)
            try:
                response = await client.post(SIMIT_URL, json=body, headers=SIMIT_HEADERS)
                if response.status_code == 200:
                    data = response.json()
                    if data is not None:
                        return {"exito": True, "datos": data, "documento": documento}
            except Exception:
                continue
    return {"exito": False, "error": "No se pudo consultar SIMIT", "documento": documento}


def formatear_respuesta(resultado: dict) -> str:
    documento = resultado.get("documento", "")
    if not resultado.get("exito"):
        return (
            f"No pude consultar SIMIT para el documento {documento}. "
            f"El sistema puede estar caído. Intenta de nuevo en unos minutos."
        )
    datos = resultado.get("datos", {})
    if not datos:
        return f"Cédula {documento}: sin comparendos ni multas registradas en SIMIT. Estado limpio."

    total_comparendos = (
        datos.get("comparendos") or datos.get("totalComparendos") or
        datos.get("cantidadComparendos") or len(datos.get("listaComparendos", [])) or 0
    )
    total_multas = (
        datos.get("multas") or datos.get("totalMultas") or
        datos.get("cantidadMultas") or len(datos.get("listaMultas", [])) or 0
    )
    valor_total = (
        datos.get("total") or datos.get("valorTotal") or
        datos.get("totalAPagar") or datos.get("saldoTotal") or 0
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
                        "description": "Número de cédula de ciudadanía o placa del vehículo. Ejemplos: '1049615965' o 'KWX584'"
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
    async with sse.connect_sse(request.scope, request.receive, request._send) as (leer, escribir):
        await mcp.run(leer, escribir, mcp.create_initialization_options())


@app.post("/messages")
async def endpoint_mensajes(request: Request):
    await sse.handle_post_message(request.scope, request.receive, request._send)


@app.post("/sse")
async def endpoint_sse_post(request: Request):
    """
    GPTmaker usa POST /sse para TODOS los mensajes MCP:
    initialize, tools/list, y tools/call.
    Manejamos cada método directamente sin SSE handler.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=200
        )

    method = body.get("method", "")
    req_id = body.get("id", 1)

    # Handshake inicial
    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "simit-movilegal", "version": "1.0"}
            }
        })

    # Lista de herramientas disponibles
    elif method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
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
                                    "description": "Número de cédula de ciudadanía o placa del vehículo. Ejemplos: '1049615965' o 'KWX584'"
                                }
                            },
                            "required": ["documento"]
                        }
                    }
                ]
            }
        })

    # Ejecución real de la herramienta — consulta SIMIT
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
                "result": {"content": [{"type": "text", "text": "Necesito el número de cédula o placa para hacer la consulta."}]}
            })

        # Consulta real a SIMIT
        resultado = await consultar_simit(documento)
        texto = formatear_respuesta(resultado)

        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": texto}]
            }
        })

    # Cualquier otro método
    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})


@app.get("/health")
async def health_check():
    return {"status": "ok", "servidor": "SIMIT MCP - Movilegal"}


@app.get("/")
async def raiz():
    return {
        "nombre": "SIMIT MCP Server - Movilegal",
        "version": "1.0",
        "herramientas": ["consultar_simit"],
        "conectar_en": "/sse"
    }


# ─── Arranque ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
