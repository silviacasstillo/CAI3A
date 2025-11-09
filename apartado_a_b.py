import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse
import secrets
import json
import qrcode


# Configuración por defecto
DEFAULT_ALGORITHM = 'SHA512'
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
SECRET_FILE = "secret.json"
ACCOUNT_NAME = "Security Team 2"
ISSUER = "Security Team 2"


def generate_base32_secret(length_bytes: int = 20) -> str:
    random_bytes = secrets.token_bytes(length_bytes)
    b32 = base64.b32encode(random_bytes).decode('utf-8')
    return b32.rstrip('=')


def build_otpauth_url(secret_base32: str, account_name: str, issuer: str,
                      algorithm: str = DEFAULT_ALGORITHM, digits: int = DEFAULT_DIGITS,
                      period: int = DEFAULT_PERIOD) -> str:
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
    return struct.pack('>Q', value)


def generate_hmac(secret_base32: str, counter: int, algorithm: str) -> bytes:
    padding = '=' * ((8 - len(secret_base32) % 8) % 8)
    key = base64.b32decode(secret_base32 + padding, casefold=True)
    msg = _int_to_bytes(counter)
    digestmod = getattr(hashlib, algorithm.lower())
    return hmac.new(key, msg, digestmod).digest()


def dynamic_truncate(hmac_digest: bytes) -> int:
    offset = hmac_digest[-1] & 0x0F
    four_bytes = hmac_digest[offset:offset + 4]
    code_int = struct.unpack('>I', four_bytes)[0] & 0x7FFFFFFF
    return code_int


def generate_totp(secret_base32: str, time_step: int = DEFAULT_PERIOD,
                  digits: int = DEFAULT_DIGITS, algorithm: str = DEFAULT_ALGORITHM,
                  for_time: int = None) -> str:
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


def save_secret(secret, filename=SECRET_FILE):
    with open(filename, 'w') as f:
        json.dump({"secret": secret}, f)


def load_secret(filename=SECRET_FILE):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
            return data["secret"]
    return None


def generate_and_save_secret():
    secret = generate_base32_secret()
    save_secret(secret)
    return secret


def generate_qr(url):
    qrcode.make(url).save("totp_qr.png")
    print("QR guardado como 'totp_qr.png' (escanea con FreeOTP)")


def main():
    secret = load_secret()
    if not secret:
        print("No se encontró clave secreta guardada.")
        secret = generate_and_save_secret()
        print("Nueva clave secreta generada y guardada en secret.json")

    otpauth_url = build_otpauth_url(secret, ACCOUNT_NAME, ISSUER)
    
    while True:
        print("\n--- MENÚ DE AUTENTICACIÓN TOTP ---")
        print("1. Dar de alta un nuevo dispositivo")
        print("2. Reutilizar dispositivo existente para verificar código")
        print("3. Salir")
        choice = input("Elige una opción: ").strip()

        if choice == '1':
            # Mostrar QR para escanear
            generate_qr(otpauth_url)
            print("Escanea el código QR con FreeOTP en tu móvil.")
            print(f"URL para regenerar QR: {otpauth_url}")

        elif choice == '2':
            # Pedir código para validar
            token = input("Introduce el código de 6 dígitos que ves en FreeOTP: ").strip()
            if verify_totp(token, secret):
                print("¡Código válido! Autenticación exitosa.")
            else:
                print("Código inválido o expirado. Intenta de nuevo.")

        elif choice == '3':
            print("Saliendo...")
            break
        else:
            print("Opción no válida, intenta de nuevo.")


if __name__ == '__main__':
    main()