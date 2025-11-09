"""
Implementación de autenticación TOTP (RFC 6238) para el Hospital.
Versión con persistencia de la clave secreta y generación automática de QR.
Autor: Security Team 2
"""

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse
import secrets
import json
import qrcode  # asegúrate de tenerlo instalado: pip install qrcode[pil]

# ---------------------- Configuración ----------------------
DEFAULT_ALGORITHM = 'SHA1'
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
SECRET_FILE = "secret.json"
ACCOUNT_NAME = "Security Team 2"
ISSUER = "Security Team 2"
# -----------------------------------------------------------


def generate_base32_secret(length_bytes: int = 20) -> str:
    """Genera una clave secreta segura codificada en Base32."""
    random_bytes = secrets.token_bytes(length_bytes)
    b32 = base64.b32encode(random_bytes).decode('utf-8')
    return b32.rstrip('=')


def build_otpauth_url(secret_base32: str, account_name: str, issuer: str,
                      algorithm: str = DEFAULT_ALGORITHM, digits: int = DEFAULT_DIGITS,
                      period: int = DEFAULT_PERIOD) -> str:
    """Construye la URL otpauth:// compatible con FreeOTP."""
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    query = {
        'secret': secret_base32,
        'issuer': issuer,
        'algorithm': algorithm,
        'digits': str(digits),
        'period': str(period)
    }
    q = urllib.parse.urlencode(query)
    return f"otpauth://totp/{label}?{q}"


def _int_to_bytes(value: int) -> bytes:
    """Convierte un entero a 8 bytes big-endian (counter)."""
    return struct.pack('>Q', value)


def generate_hmac(secret_base32: str, counter: int, algorithm: str) -> bytes:
    """Genera el HMAC con la clave y el contador."""
    padding = '=' * ((8 - len(secret_base32) % 8) % 8)
    key = base64.b32decode(secret_base32 + padding, casefold=True)
    msg = _int_to_bytes(counter)
    digestmod = getattr(hashlib, algorithm.lower())
    return hmac.new(key, msg, digestmod).digest()


def dynamic_truncate(hmac_digest: bytes) -> int:
    """Truncamiento dinámico (RFC4226). Extrae un entero de 31 bits del HMAC."""
    offset = hmac_digest[-1] & 0x0F
    four_bytes = hmac_digest[offset:offset + 4]
    code_int = struct.unpack('>I', four_bytes)[0] & 0x7FFFFFFF
    return code_int


def generate_totp(secret_base32: str, time_step: int = DEFAULT_PERIOD,
                  digits: int = DEFAULT_DIGITS, algorithm: str = DEFAULT_ALGORITHM,
                  for_time: int = None) -> str:
    """Genera el código TOTP actual."""
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time // time_step)
    hmac_digest = generate_hmac(secret_base32, counter, algorithm)
    code_int = dynamic_truncate(hmac_digest)
    otp = code_int % (10 ** digits)
    return str(otp).zfill(digits)


def verify_totp(token: str, secret_base32: str, window: int = 2,
                time_step: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS,
                algorithm: str = DEFAULT_ALGORITHM, for_time: int = None) -> bool:
    """Verifica el código TOTP dentro de una ventana de ±2 intervalos (60s)."""
    if for_time is None:
        for_time = int(time.time())
    token = token.strip()
    if not token.isdigit():
        return False
    for offset in range(-window, window + 1):
        t = for_time + offset * time_step
        expected = generate_totp(secret_base32, time_step=time_step,
                                 digits=digits, algorithm=algorithm, for_time=t)
        if hmac.compare_digest(expected, token):
            return True
    return False


# ------------------------------- MAIN ---------------------------------
if __name__ == '__main__':
    # 1️⃣ Cargar o generar la secret
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r") as f:
            data = json.load(f)
            secret = data["secret"]
            print("Clave secreta cargada desde secret.json")
    else:
        secret = generate_base32_secret(20)
        with open(SECRET_FILE, "w") as f:
            json.dump({"secret": secret}, f)
            print("Nueva clave secreta generada y guardada en secret.json")

    # 2️⃣ Construir URL y QR
    otpauth_url = build_otpauth_url(secret, ACCOUNT_NAME, ISSUER)
    qrcode.make(otpauth_url).save("totp_qr.png")

    print("\n--- TOTP SERVER DEMO -------------------------------------------")
    print("Secret (Base32):", secret)
    print("URL otpauth (puede usarse para regenerar el QR):")
    print(otpauth_url)
    print("QR guardado como 'totp_qr.png' (escanea con FreeOTP)")
    print("---------------------------------------------------------------")

    # 3️⃣ Mostrar código actual
    current_otp = generate_totp(secret)
    print("Código TOTP actual (servidor):", current_otp)

    # 4️⃣ Validar manualmente un código desde FreeOTP
    user_token = input("\nIntroduce el código de 6 dígitos que ves en FreeOTP: ")
    is_valid = verify_totp(user_token, secret)
    print("¿El código es válido?:", is_valid)
    print("---------------------------------------------------------------")
