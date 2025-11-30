import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_CHAIN_PATH = os.path.join(BASE_DIR, "keys", "ca_chain.pem")
AUTH_CERT_PATH = os.path.join(BASE_DIR, "keys", "auth.crt.pem")
AUTH_KEY_PATH = os.path.join(BASE_DIR, "keys", "auth.key.pem")
BALLOT_CERT_PATH = os.path.join(BASE_DIR, "keys", "ballot.crt.pem")
BALLOT_KEY_PATH = os.path.join(BASE_DIR, "keys", "ballot.key.pem")


def verify_with_openssl(cert_path: str) -> bool:
    """verifica certificado x.509 con openssl"""
    try:
        res = subprocess.run(["openssl", "verify", "-CAfile", CA_CHAIN_PATH,
                    cert_path], capture_output=True, text=True, check=False)
        print(f"[PKI] verify cert_path: {res.stdout.strip()} {res.stderr.strip()}")
        return "OK" in res.stdout
    # a lo mejor una excepción demasiada amplia?
    except Exception as e:
        print(f"[PKI] Error ejecutando openssl verify: {e}")
        return False


def load_private_key(path:str, password: str):
    """carga una clave privada RSA protegida con passphrase
    'password' debe ser la misma que la usada en openssl"""
    if not password:
        raise ValueError("Se requiere la contraseña para cargar la clave privada")

    with open(path, "rb") as f:
        pem = f.read()

    return serialization.load_pem_private_key(pem,
                                            password=password.encode("utf-8"))


def load_public_key(cert_path: str):
    """obtiene la clave pública de un certificado x.509"""
    with open(cert_path, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data)
    return cert.public_key()