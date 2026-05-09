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

# URL del API interno de SIMIT (sin captcha, sin login)
SIMIT_URL = "https://consultasimit.fcm.org.co/simit/microservices/estado-cuenta-simit/estadocuenta/consulta"

# Headers que simulan el navegador para que SIMIT acepte la petición
SIMIT_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://www.fcm.org.co",
    "Referer": "https://www.fcm.org.co/simit/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "es-CO,es;q=0.9,es-419;q=0.8",
}

# Formatos de body a intentar (SIMIT puede esperar diferentes nombres de campo)
FORMATOS_BODY = [
    lambda doc: {"noIdentificacion": doc},
    lambda doc: {"numeroDocumento": doc},
    lambda doc: {"identificacion": doc},
    lambda doc: {"cedula": doc},
    lambda doc: {"documento": doc},
]


# ─── Lógica de consulta SIMIT ─────────────────────────────────────────────────

async def consultar_simit(documento: str) -> dict:
    """
    Consulta SIMIT con el número de cédula o placa.
    Prueba varios formatos de body hasta encontrar el que funciona.
    Retorna un dict con los resultados o un error.
    """
    documento = documento.strip().upper()

    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        for formato in FORMATOS_BODY:
            body = formato(documento)
            try:
                response = await client.post(
                    SIMIT_URL,
                    json=body,
                    headers=SIMIT_HEADERS
                )
                if response.status_code == 200:
                    data = response.json()
                    # Si retorna datos válidos, usamos este formato
                    if data is not None:
                        return {"exito": True, "datos": data, "documento": documento}
            except Exception:
                continue  # Intentar el siguiente formato

    return {
        "exito": False,
        "error": "No se pudo consultar SIMIT",
        "documento": documento
    }


def formatear_respuesta(resultado: dict) -> str:
    """
    Convierte la respuesta cruda de SIMIT en un texto claro
    que Luisa puede leer y explicar al cliente.
    """
    documento = resultado.get("documento", "")

    # Si hubo error de conexión
    if not resultado.get("exito"):
        return (
            f"No pude consultar SIMIT para el documento {documento}. "
            f"El sistema puede estar caído. Intenta de nuevo en unos minutos."
        )

    datos = resultado.get("datos", {})

    # Manejar respuesta vacía o sin deudas
    if not datos:
        return f"Cédula {documento}: sin comparendos ni multas registradas en SIMIT. Estado limpio."

    # Extraer campos (SIMIT puede usar diferentes nombres según la versión)
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

    # Sin deudas
    if valor_total == 0 and total_comparendos == 0 and total_multas == 0:
        return f"Cédula {documento}: sin comparendos ni multas en SIMIT. Estado limpio."

    # Con deudas — armar resumen
    lineas = [f"Consulta SIMIT - Documento {documento}:"]
    if total_comparendos:
        lineas.append(f"Comparendos: {total_comparendos}")
    if total_multas:
        lineas.append(f"Multas: {total_multas}")
    if valor_total:
        lineas.append(f"Total a pagar: ${int(valor_total):,}")

    # Agregar detalle de comparendos si está disponible
    lista = datos.get("listaComparendos", datos.get("comparendosList", []))
    if lista:
        lineas.append("Detalle:")
        for item in lista[:5]:  # Máximo 5 para no saturar el mensaje
            placa = item.get("placa", item.get("noPlaca", ""))
            estado = item.get("estado", item.get("estadoComparendo", ""))
            valor = item.get("valorAPagar", item.get("valor", 0))
            secretaria = item.get("secretaria", item.get("organismoTransito", ""))
            if placa or estado:
                lineas.append(f"  - Placa {placa} | {secretaria} | {estado} | ${int(valor):,}")

    lineas.append("Movilegal puede ayudarte a gestionar estos comparendos.")
    return "\n".join(lineas)


# ─── Servidor MCP ─────────────────────────────────────────────────────────────

# Crear el servidor MCP con nombre identificable
mcp = Server("simit-movilegal")


@mcp.list_tools()
async def listar_herramientas():
    """Le dice a GPTmaker qué herramientas tiene disponibles este servidor."""
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
    """Ejecuta la herramienta cuando Luisa la llama."""
    if name != "consultar_simit":
        return [TextContent(type="text", text=f"Herramienta '{name}' no existe en este servidor.")]

    documento = arguments.get("documento", "").strip()

    if not documento:
        return [TextContent(type="text", text="Necesito el número de cédula o placa para hacer la consulta.")]

    # Hacer la consulta a SIMIT
    resultado = await consultar_simit(documento)

    # Formatear y retornar
    texto = formatear_respuesta(resultado)
    return [TextContent(type="text", text=texto)]


# ─── App FastAPI + SSE Transport ──────────────────────────────────────────────

app = FastAPI(title="SIMIT MCP - Movilegal")

# CORS para que GPTmaker pueda conectarse sin problemas de origen
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
    """
    Punto de conexión principal para GPTmaker.
    GPTmaker se conecta aquí vía Server-Sent Events.
    """
    async with sse.connect_sse(
        request.scope,
        request.receive,
        request._send
    ) as (leer, escribir):
        await mcp.run(
            leer,
            escribir,
            mcp.create_initialization_options()
        )


@app.post("/messages")
async def endpoint_mensajes(request: Request):
    """Recibe mensajes de GPTmaker vía /messages."""
    await sse.handle_post_message(
        request.scope,
        request.receive,
        request._send
    )


@app.post("/sse")
async def endpoint_sse_post(request: Request):
    """
    GPTmaker valida el servidor haciendo POST /sse.
    Lo redirigimos al handler de mensajes para que funcione correctamente.
    """
    await sse.handle_post_message(
        request.scope,
        request.receive,
        request._send
    )


@app.get("/health")
async def health_check():
    """Railway usa este endpoint para saber si el servidor está vivo."""
    return {"status": "ok", "servidor": "SIMIT MCP - Movilegal"}


@app.get("/")
async def raiz():
    """Página de inicio para confirmar que el servidor corre."""
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
