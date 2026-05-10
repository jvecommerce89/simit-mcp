"""
Servidor MCP - Consulta SIMIT Colombia
Para Luisa de Movilegal en GPTmaker â v4.7

Algoritmo de captcha reverse-engineered de captcha-worker.js:
1. time = int(time.time())  [client-side]
2. POST api.php endpoint=question â retorna {datos: {pregunta, dificultad_recomendada}}
3. Para i in range(difficulty):
   - Busca nonce (primo) tal que SHA256(JSON({question,time,nonce})).startswith("0000")
   - verification.append([question, time, nonce])  # ARRAY, no dict
4. EnvÃ­a verification como reCaptchaDTO.response (array de arrays) a SIMIT

Fixes v4.4:
- API devuelve "datos"/"pregunta"/"dificultad_recomendada" (espaÃ±ol), no "data"/"question"
- reCaptchaDTO.response se envÃ­a como array real (no string JSON)
- consumidor como integer 1 (no string "1")

Fix v4.5:
- verify_array era dict {"question":..,"time":..,"nonce":..} â debe ser [question, time, nonce]
  (JS hace: verification.push([question, time, nonce]) â array de arrays)

Fix v4.7:
- Usar curl_cffi con impersonate="chrome124" para el POST a SIMIT.
  Simula el TLS fingerprint (JA3/AKAMAI) exacto de Chrome â los anti-bots detectan
  httpx/Python por el handshake TLS aunque los headers sean correctos.
  El captcha sigue usando httpx (qxcaptcha.fcm.org.co no filtra por TLS).
"""

import os
import time as time_module
import hashlib
import json
import httpx
from curl_cffi.requests import AsyncSession as CurlSession
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

# âââ ConfiguraciÃ³n ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Captcha (algoritmo real de captcha-worker.js) ââââââââââââââââââââââââââââ

def es_primo(n: int) -> bool:
    """
    Mismo resultado que isPrime() del captcha-worker.js pero O(sqrt(n)) en vez de O(n).
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
    ImplementaciÃ³n exacta de solveCaptcha() del captcha-worker.js:
    sha256(JSON({question, time, nonce})).startsWith("0000") && isPrime(nonce)

    OptimizaciÃ³n: pre-formatear el prefijo constante una sola vez (~4x mÃ¡s rÃ¡pido).
    """
    prefijo = f'{{"question":"{question}","time":{captcha_time},"nonce":'.encode()
    sufijo = b'}'

    nonce = nonce_inicial + 1  # worker empieza en 1 y hace nonce++ inmediatamente
    while True:
        data = prefijo + str(nonce).encode() + sufijo
        hash_actual = hashlib.sha256(data).hexdigest()

        if hash_actual[:4] == "0000" and es_primo(nonce):
            return {
                # FIX v4.5: JS hace verification.push([question, time, nonce]) â array, no dict
                "verify_array": [question, captcha_time, nonce],
                "nonce": nonce,
                "hash": hash_actual,
            }
        nonce += 1


async def obtener_question(client: httpx.AsyncClient) -> dict:
    """
    Llama api.php con endpoint=question (FormData, igual que captcha.js).
    La API devuelve: {"error":false,"datos":{"pregunta":"...","dificultad_recomendada":N}}
    Mapea a {question, recommended_difficulty} para uso interno.
    """
    try:
        r = await client.post(
            CAPTCHA_URL,
            data={"endpoint": "question"},
            headers=CAPTCHA_HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            # La API usa "datos" (espaÃ±ol) â soportar tambiÃ©n "data" por si cambia
            datos = data.get("datos") or data.get("data")
            if not data.get("error") and isinstance(datos, dict):
                resultado = {
                    # La API usa "pregunta" â mapeamos a "question" para el PoW
                    "question": datos.get("pregunta") or datos.get("question"),
                    # La API usa "dificultad_recomendada"
                    "recommended_difficulty": datos.get("dificultad_recomendada") or datos.get("recommended_difficulty", 2),
                }
                resultado["_headers"] = dict(r.headers)
                resultado["_cookies"] = dict(r.cookies)
                return resultado
    except Exception:
        pass
    return {}


def construir_captcha_response(question: str, captcha_time: int, difficulty: int) -> list:
    """
    Loop del captcha-worker.js: resuelve difficulty veces, acumulando el array.
    Retorna lista de dicts (no string) para enviar directamente como JSON array.
    """
    verification = []
    nonce = 1
    for _ in range(difficulty):
        resultado = resolver_captcha(question, captcha_time, nonce)
        nonce = resultado["nonce"]
        verification.append(resultado["verify_array"])
    return verification


# âââ LÃ³gica de consulta SIMIT âââââââââââââââââââââââââââââââââââââââââââââââââ

async def prefetch_session_cookies(client: httpx.AsyncClient) -> dict:
    """
    Fix v4.6: Visita fcm.org.co/simit/ antes de la consulta para obtener
    cookies de sesiÃ³n reales (igual que un browser al cargar la pÃ¡gina).
    SIMIT puede requerir estas cookies ademÃ¡s de las del captcha.
    """
    urls_a_visitar = [
        "https://www.fcm.org.co/simit/",
        "https://consultasimit.fcm.org.co/simit/microservices/estado-cuenta-simit/estadocuenta/consulta",
    ]
    session_cookies = {}
    for url in urls_a_visitar[:1]:  # solo la principal por ahora
        try:
            r = await client.get(
                url,
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
    captcha_time = int(time_module.time())  # Math.floor(Date.now()/1000)

    async with httpx.AsyncClient(timeoout=60, follow_redirects=True) as client:
        # Paso 0 (v4.6): pre-fetch cookies de sesiÃ³n del sitio principal
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

        # Paso 2: proof-of-work con SHA256
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

        # Paso 3: construir body con array real (no string)
        body = {
            "filtro": documento,
            "reCaptchaDTO": {
                "response": pow_array,  # array real, igual que el browser
                "consumidor": 1,        # integer, igual que $CONSTANTBÕS\Ñ]XÙKTÒÕÔKÒ¢FöF5ö6öö¶W2Ò²¢§6W76öåö6öö¶W2Â¢¦6F6ö6öö¶W7Ò26F66ö'&VW67&&R66öæfÆ7Fð¢6öö¶U÷7G"Ò#²"æ¦öâb'¶·Ó×·gÒ"f÷"²ÂbâFöF5ö6öö¶W2æFV×2¢6ÖEöVFW'5÷&WÒ²¢¥4ÔEôTDU%7Ð¢b6öö¶U÷7G# ¢6ÖEöVFW'5÷&W²$6öö¶R%ÒÒ6öö¶U÷7G ¢FV'Vuöæfõ²&6öö¶UöVçfFö÷6ÖB%ÒÒ6öö¶U÷7G%³£#Òb6öö¶U÷7G"VÇ6R&ææwVæ  ¢G' ¢2fcBãs¢7W&Åö6ff6öâ×W'6öæFSÒ&6&öÖS#B"(	BDÅ2fævW'&çBL:çF6ð¢2Â'&÷w6W"&VÂâGGW6DÅ2W7L:æF"FöâVRÆ÷2çFÖ&÷G2FWFV7Fâà¢7æ2vF7W&Å6W76öâ×W'6öæFSÒ&6&öÖS#B"27W&Ã ¢&W7öç6RÒvB7W&Âç÷7B¢4ÔEõU$ÂÀ¢§6öãÖ&öGÀ¢VFW'3×6ÖEöVFW'5÷&WÀ¢FÖV÷WCÓ#À¢ ¢&u÷7FGW2Ò&W7öç6Rç7FGW5ö6öFP¢&u÷FWBÒ&W7öç6RçFWE³£Ð¢6ÖEöVFW'2ÒF7B&W7öç6RæVFW'2 ¢b&W7öç6Rç7FGW5ö6öFRÓÒ# ¢FFÒ&W7öç6Ræ§6öâ¢&WGW&â°¢&WFò#¢G'VRÀ¢&FF÷2#¢FFÀ¢&Fö7VÖVçFò#¢Fö7VÖVçFòÀ¢&FV'Vr#¢²¢¦FV'VuöæfòÂ'7FGW2#¢&u÷7FGW7ÒÀ¢Ð¢VÇ6S ¢&WGW&â°¢&WFò#¢fÇ6RÀ¢&W'&÷"#¢b%4ÔB&W7öæF;2·&W7öç6Rç7FGW5ö6öFWÒ"À¢&Fö7VÖVçFò#¢Fö7VÖVçFòÀ¢&FV'Vr#¢°¢¢¦FV'VuöæfòÀ¢'7FGW2#¢&u÷7FGW2À¢&&öG÷&WfWr#¢&u÷FWBÀ¢'6ÖE÷&W7öç6UöVFW'2#¢6ÖEöVFW'2À¢ÒÀ¢Ð ¢W6WBGGä6öææV7DW'&÷"2S ¢&WGW&â°¢&WFò#¢fÇ6RÀ¢&W'&÷"#¢b$æò6RVFò6öæV7F"4ÔC¢·7G"R³£×Ò"À¢&Fö7VÖVçFò#¢Fö7VÖVçFòÀ¢&FV'Vr#¢²¢¦FV'VuöæfòÂ'Fò#¢$6öææV7DW'&÷"'ÒÀ¢Ð¢W6WBW6WFöâ2S ¢&WGW&â°¢&WFò#¢fÇ6RÀ¢&W'&÷"#¢b$W'&÷"6öç7VÇFæFò4ÔC¢·7G"R³£×Ò"À¢&Fö7VÖVçFò#¢Fö7VÖVçFòÀ¢&FV'Vr#¢²¢¦FV'VuöæfòÂ'Fò#¢GRRåõöæÖUõ÷ÒÀ¢Ð  ¦FVbf÷&ÖFV%÷&W7VW7F&W7VÇFFó¢F7BÓâ7G# ¢Fö7VÖVçFòÒ&W7VÇFFòævWB&Fö7VÖVçFò"Â"" ¢bæ÷B&W7VÇFFòævWB&WFò" ¢W'&÷"Ò&W7VÇFFòævWB&W'&÷""Â""¢FV'VrÒ&W7VÇFFòævWB&FV'Vr"Â·Ò¢7FGW2ÒFV'VrævWB'7FGW2"Â#ò" ¢b7FGW2ÓÒC ¢&WGW&â¢b$æòVFR6öç7VÇF"4ÔB&¶Fö7VÖVçF÷Òâ ¢b$6F6&V6¦FòW'&÷"Câ÷"ff÷"çFVçFFRçVWfòâ ¢¢VÆb7FGW2ÓÒS3 ¢&WGW&â¢b$æòVFR6öç7VÇF"4ÔB&¶Fö7VÖVçF÷Òâ ¢b%6W'fF÷"4ÔB6:ÖFòW'&÷"S2â6öç7VÇFF&V7FÖVçFRVâf6Òæ÷&ræ6ò÷6ÖB ¢¢VÇ6S ¢&WGW&â¢b$æòVFR6öç7VÇF"4ÔB&¶Fö7VÖVçF÷Òâ ¢b$çFVçFFRçVWfòVâVæ÷2ÖçWF÷2âW'&÷#¢¶W'&÷'Ò ¢ ¢FF÷2Ò&W7VÇFFòævWB&FF÷2"Â·Ò ¢bæ÷BFF÷3 ¢&WGW&âb$<:GVÆ¶Fö7VÖVçF÷Ó¢6â6ö×&VæF÷2æ×VÇF2Vâ4ÔBâW7FFòÆ×òâ  ¢F÷FÅö6ö×&VæF÷2Ò¢FF÷2ævWB&6ö×&VæF÷2"÷ ¢FF÷2ævWB'F÷FÄ6ö×&VæF÷2"÷ ¢FF÷2ævWB&6çFFD6ö×&VæF÷2"÷ ¢ÆVâFF÷2ævWB&Æ7F6ö×&VæF÷2"ÂµÒ÷" ¢¢F÷FÅö×VÇF2Ò¢FF÷2ævWB&×VÇF2"÷ ¢FF÷2ævWB'F÷FÄ×VÇF2"÷ ¢FF÷2ævWB&6çFFD×VÇF2"÷ ¢ÆVâFF÷2ævWB&Æ7F×VÇF2"ÂµÒ÷" ¢¢fÆ÷%÷F÷FÂÒ¢FF÷2ævWB'F÷FÂ"÷ ¢FF÷2ævWB'fÆ÷%F÷FÂ"÷ ¢FF÷2ævWB'F÷FÄv""÷ ¢FF÷2ævWB'6ÆFõF÷FÂ"÷" ¢ ¢bfÆ÷%÷F÷FÂÓÒæBF÷FÅö6ö×&VæF÷2ÓÒæBF÷FÅö×VÇF2ÓÒ ¢&WGW&âb$<:GVÆ¶Fö7VÖVçF÷Ó¢6â6ö×&VæF÷2æ×VÇF2Vâ4ÔBâW7FFòÆ×òâ  ¢ÆæV2Ò¶b$6öç7VÇF4ÔBÒFö7VÖVçFò¶Fö7VÖVçF÷Ó¢%Ð¢bF÷FÅö6ö×&VæF÷3 ¢ÆæV2æVæBb$6ö×&VæF÷3¢·F÷FÅö6ö×&VæF÷7Ò"¢bF÷FÅö×VÇF3 ¢ÆæV2æVæBb$×VÇF3¢·F÷FÅö×VÇF7Ò"¢bfÆ÷%÷F÷FÃ ¢ÆæV2æVæBb%F÷FÂv#¢G¶çBfÆ÷%÷F÷FÂ¢ÇÒ" ¢Æ7FÒFF÷2ævWB&Æ7F6ö×&VæF÷2"ÂFF÷2ævWB&6ö×&VæF÷4Æ7B"ÂµÒ¢bÆ7F ¢ÆæV2æVæB$FWFÆÆS¢"¢f÷"FVÒâÆ7F³£UÓ ¢Æ6ÒFVÒævWB'Æ6"ÂFVÒævWB&æõÆ6"Â""¢W7FFòÒFVÒævWB&W7FFò"ÂFVÒævWB&W7FFô6ö×&VæFò"Â""¢fÆ÷"ÒFVÒævWB'fÆ÷$v""ÂFVÒævWB'fÆ÷""Â¢6V7&WF&ÒFVÒævWB'6V7&WF&"ÂFVÒævWB&÷&væ6ÖõG&ç6Fò"Â""¢bÆ6÷"W7FFó ¢ÆæV2æVæBb"ÒÆ6·Æ6ÒÂ·6V7&WF&ÒÂ¶W7FF÷ÒÂG¶çBfÆ÷"¢ÇÒ" ¢ÆæV2æVæB$Ö÷fÆVvÂVVFRVF'FRvW7Föæ"W7F÷26ö×&VæF÷2â"¢&WGW&â%Æâ"æ¦öâÆæV2  ¢2)H)H)H6W'fF÷"Ô5)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H  ¦Ö7Ò6W'fW"'6ÖBÖÖ÷fÆVvÂ"  ¤Ö7æÆ7E÷FööÇ2¦7æ2FVbÆ7F%öW'&ÖVçF2 ¢&WGW&â°¢FööÂ¢æÖSÒ&6öç7VÇF%÷6ÖB"À¢FW67&FöãÒ¢$6öç7VÇF6ö×&VæF÷2Â×VÇF2Ræg&66öæW2FRG,:ç6FòVâ4ÔB6öÆöÖ&â ¢,9§6Æ7VæFòVÂ6ÆVçFR&÷÷&6öæR7R<:GVÆFR6VFFì:ÖòÆ6FVÂfV:Ö7VÆòâ ¢À¢çWE66VÖ×°¢'GR#¢&ö&¦V7B"À¢'&÷W'FW2#¢°¢&Fö7VÖVçFò#¢°¢'GR#¢'7G&ær"À¢&FW67&Föâ#¢$ì;¦ÖW&òFR<:GVÆòÆ6âV¦V×Æ÷3¢sCcScRròtµuSBr"À¢Ð¢ÒÀ¢'&WV&VB#¢²&Fö7VÖVçFò%ÒÀ¢ÒÀ¢¢Ð  ¤Ö7æ6ÆÅ÷FööÂ¦7æ2FVbV¦V7WF%öW'&ÖVçFæÖS¢7G"Â&wVÖVçG3¢F7B ¢bæÖRÒ&6öç7VÇF%÷6ÖB# ¢&WGW&âµFWD6öçFVçBGSÒ'FWB"ÂFWCÖb$W'&ÖVçFw¶æÖWÒræòW7FRâ"Ð ¢Fö7VÖVçFòÒ&wVÖVçG2ævWB&Fö7VÖVçFò"Â""ç7G&¢bæ÷BFö7VÖVçFó ¢&WGW&âµFWD6öçFVçBGSÒ'FWB"ÂFWCÒ$æV6W6FòVÂì;¦ÖW&òFR<:GVÆòÆ6â"Ð ¢&W7VÇFFòÒvB6öç7VÇF%÷6ÖBFö7VÖVçFò¢FWFòÒf÷&ÖFV%÷&W7VW7F&W7VÇFFò¢&WGW&âµFWD6öçFVçBGSÒ'FWB"ÂFWC×FWFòÐ  ¢2)H)H)Hf7D)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H  ¦Òf7DFFÆSÒ%4ÔBÔ5ÒÖ÷fÆVvÂ" ¦æFEöÖFFÆWv&R¢4õ%4ÖFFÆWv&RÀ¢ÆÆ÷uö÷&vç3Õ²"¢%ÒÀ¢ÆÆ÷uö7&VFVçFÇ3ÕG'VRÀ¢ÆÆ÷uöÖWFöG3Õ²"¢%ÒÀ¢ÆÆ÷uöVFW'3Õ²"¢%ÒÀ¢ §76RÒ76U6W'fW%G&ç7÷'B"öÖW76vW2"  ¤ævWB"÷76R"¦7æ2FVbVæGöçE÷76R&WVW7C¢&WVW7B ¢7æ2vF76Ræ6öææV7E÷76R¢&WVW7Bç66÷RÀ¢&WVW7Bç&V6VfRÀ¢&WVW7Bå÷6VæBÀ¢2ÆVW"ÂW67&&" ¢vBÖ7ç'VâÆVW"ÂW67&&"ÂÖ7æ7&VFUöæFÆ¦Föåö÷Föç2  ¤ç÷7B"öÖW76vW2"¦7æ2FVbVæGöçEöÖVç6¦W2&WVW7C¢&WVW7B ¢vB76RææFÆU÷÷7EöÖW76vR&WVW7Bç66÷RÂ&WVW7Bç&V6VfRÂ&WVW7Bå÷6VæB  ¤ç÷7B"÷76R"¦7æ2FVbVæGöçE÷76U÷÷7B&WVW7C¢&WVW7B ¢G' ¢&öGÒvB&WVW7Bæ§6öâ¢W6WBW6WFöã ¢&WGW&â¥4ôå&W7öç6R¢²&§6öç'2#¢#"ã"Â&B#¢æöæRÂ&W'&÷"#¢²&6öFR#¢Ó3#sÂ&ÖW76vR#¢%'6RW'&÷"'×ÒÀ¢7FGW5ö6öFSÓ#À¢ ¢ÖWFöBÒ&öGævWB&ÖWFöB"Â""¢&WöBÒ&öGævWB&B"Â ¢bÖWFöBÓÒ&æFÆ¦R# ¢&WGW&â¥4ôå&W7öç6R°¢&§6öç'2#¢#"ã"Â&B#¢&WöBÀ¢'&W7VÇB#¢°¢'&÷Fö6öÅfW'6öâ#¢###BÓÓR"À¢&6&ÆFW2#¢²'FööÇ2#¢·×ÒÀ¢'6W'fW$æfò#¢²&æÖR#¢'6ÖBÖÖ÷fÆVvÂ"Â'fW'6öâ#¢#BãB'ÒÀ¢ÒÀ¢Ò ¢VÆbÖWFöBÓÒ'FööÇ2öÆ7B# ¢&WGW&â¥4ôå&W7öç6R°¢&§6öç'2#¢#"ã"Â&B#¢&WöBÀ¢'&W7VÇB#¢°¢'FööÇ2#¢·°¢&æÖR#¢&6öç7VÇF%÷6ÖB"À¢&FW67&Föâ#¢$6öç7VÇF6ö×&VæF÷2×VÇF2Vâ4ÔB6öÆöÖ&â"À¢&çWE66VÖ#¢°¢'GR#¢&ö&¦V7B"À¢'&÷W'FW2#¢°¢&Fö7VÖVçFò#¢²'GR#¢'7G&ær"Â&FW67&Föâ#¢$<:GVÆòÆ6â'ÒÀ¢ÒÀ¢'&WV&VB#¢²&Fö7VÖVçFò%ÒÀ¢ÒÀ¢ÕÒÀ¢ÒÀ¢Ò ¢VÆbÖWFöBÓÒ'FööÇ2ö6ÆÂ# ¢&×2Ò&öGævWB'&×2"Â·Ò¢FööÅöæÖRÒ&×2ævWB&æÖR"Â""¢&wVÖVçG2Ò&×2ævWB&&wVÖVçG2"Â·Ò ¢bFööÅöæÖRÒ&6öç7VÇF%÷6ÖB# ¢&WGW&â¥4ôå&W7öç6R°¢&§6öç'2#¢#"ã"Â&B#¢&WöBÀ¢&W'&÷"#¢²&6öFR#¢Ó3#c"Â&ÖW76vR#¢b$W'&ÖVçFw·FööÅöæÖWÒræòW7FRâ'ÒÀ¢Ò ¢Fö7VÖVçFòÒ&wVÖVçG2ævWB&Fö7VÖVçFò"Â""ç7G&¢bæ÷BFö7VÖVçFó ¢&WGW&â¥4ôå&W7öç6R°¢&§6öç'2#¢#"ã"Â&B#¢&WöBÀ¢'&W7VÇB#¢²&6öçFVçB#¢·²'GR#¢'FWB"Â'FWB#¢$æV6W6Fò<:GVÆòÆ6â'Õ×ÒÀ¢Ò ¢
