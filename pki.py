import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = "keys"
OPENSSL_CONFIG = os.path.join(KEYS_DIR, "openssl.cnf")
CA_ROOT_KEY = os.path.join(KEYS_DIR, "ca_root.key.pem")
CA_ROOT_CRT = os.path.join(KEYS_DIR, "ca_root.crt.pem")
CA_SUB_KEY = os.path.join(KEYS_DIR, "ca_sub.key.pem")
CA_SUB_CRT = os.path.join(KEYS_DIR, "ca_sub.crt.pem")
AUTH_KEY = os.path.join(KEYS_DIR, "auth.key.pem")
AUTH_CRT = os.path.join(KEYS_DIR, "auth.crt.pem")
BALLOT_KEY = os.path.join(KEYS_DIR, "ballot.key.pem")
BALLOT_CRT = os.path.join(KEYS_DIR, "ballot.crt.pem")
CA_CHAIN = os.path.join(KEYS_DIR, "ca_chain.pem")
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

def generating_pki(root_password: str, sub_password: str, auth_password: str,
                   ballot_password: str) -> None:
    """ genera todo el pki, si no existe, con ssl.
    root CA, sub CA, AuthServer, BallotBox, cadena (ca_chain.pem)"""
    # si existe, asumimos que todo está creado
    if os.path.exists(AUTH_KEY) and os.path.exists(BALLOT_KEY):
        print("[PKI] Claves ya existentes, no se regenera la PKI.")
        return

    os.makedirs(KEYS_DIR, exist_ok=True)

    # ROOT
    print("[PKI] Generando Root CA...")
    subprocess.run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-aes-256-cbc",
        "-pkeyopt", "rsa_keygen_bits:4096",
        "-pass", f"pass:{root_password}",
        "-out", CA_ROOT_KEY
    ], check=True)

    subprocess.run([
        "openssl", "req",
        "-config", OPENSSL_CONFIG,
        "-x509", "-new",
        "-key", CA_ROOT_KEY,
        "-passin", f"pass:{root_password}",
        "-sha256", "-days", "3650",
        "-subj", "/C=ES/O=VotePKI/OU=RootCA/CN=Vote Root CA",
        "-out", CA_ROOT_CRT
    ], check=True)

    # SUBROOT
    print("[PKI] Generando Sub CA...")
    subprocess.run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-aes-256-cbc",
        "-pkeyopt", "rsa_keygen_bits:4096",
        "-pass", f"pass:{sub_password}",
        "-out", CA_SUB_KEY],
        check=True)

    subprocess.run([
        "openssl", "req",
        "-config", OPENSSL_CONFIG,
        "-new",
        "-key", CA_SUB_KEY,
        "-passin", f"pass:{sub_password}",
        "-subj", "/C=ES/O=VotePKI/OU=SubCA/CN=Vote Sub CA",
        "-out", os.path.join(KEYS_DIR, "ca_sub.csr.pem")],
        check=True)

    subprocess.run([
        "openssl", "x509", "-req",
        "-in", os.path.join(KEYS_DIR, "ca_sub.csr.pem"),
        "-CA", CA_ROOT_CRT,
        "-CAkey", CA_ROOT_KEY,
        "-passin", f"pass:{root_password}",
        "-CAcreateserial",
        "-out", CA_SUB_CRT,
        "-days", "1825",
        "-sha256",
        "-extfile", os.path.join(KEYS_DIR, "ca_sub_ext.cnf"),
        "-extensions", "v3_ca"],
        check=True)

    # AUTHSERVER
    print("[PKI] Generando clave y certificado de AuthServer...")
    subprocess.run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-aes-256-cbc",
        "-pkeyopt", "rsa_keygen_bits:3072",
        "-pass", f"pass:{auth_password}",
        "-out", AUTH_KEY
    ], check=True)

    subprocess.run([
        "openssl", "req",
        "-config", OPENSSL_CONFIG,
        "-new",
        "-key", AUTH_KEY,
        "-passin", f"pass:{auth_password}",
        "-subj", "/C=ES/O=VoteApp/OU=AuthServer/CN=auth.local",
        "-out", os.path.join(KEYS_DIR, "auth.csr.pem")
    ], check=True)

    subprocess.run([
        "openssl", "x509", "-req",
        "-in", os.path.join(KEYS_DIR, "auth.csr.pem"),
        "-CA", CA_SUB_CRT,
        "-CAkey", CA_SUB_KEY,
        "-passin", f"pass:{sub_password}",
        "-CAcreateserial",
        "-out", AUTH_CRT,
        "-days", "365",
        "-sha256",
        "-extfile", os.path.join(KEYS_DIR, "auth_ext.cnf"),
        "-extensions", "v3_req"
    ], check=True)

    # BALLOTBOX
    print("[PKI] Generando clave y certificado de BallotBox...")
    subprocess.run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-aes-256-cbc",
        "-pkeyopt", "rsa_keygen_bits:3072",
        "-pass", f"pass:{ballot_password}",
        "-out", BALLOT_KEY
    ], check=True)

    subprocess.run([
        "openssl", "req",
        "-config", OPENSSL_CONFIG,
        "-new",
        "-key", BALLOT_KEY,
        "-passin", f"pass:{ballot_password}",
        "-subj", "/C=ES/O=VoteApp/OU=BallotBox/CN=ballot.local",
        "-out", os.path.join(KEYS_DIR, "ballot.csr.pem")
    ], check=True)

    subprocess.run([
        "openssl", "x509", "-req",
        "-in", os.path.join(KEYS_DIR, "ballot.csr.pem"),
        "-CA", CA_SUB_CRT,
        "-CAkey", CA_SUB_KEY,
        "-passin", f"pass:{sub_password}",
        "-CAcreateserial",
        "-out", BALLOT_CRT,
        "-days", "365",
        "-sha256",
        "-extfile", os.path.join(KEYS_DIR, "ballot_ext.cnf"),
        "-extensions", "v3_req"
    ], check=True)

    # CHAIN
    print("[PKI] Generando cadena de certificados (ca_chain.pem)...")
    with open(CA_CHAIN, "wb") as f_out, \
         open(CA_SUB_CRT, "rb") as f_sub, \
         open(CA_ROOT_CRT, "rb") as f_root:
        f_out.write(f_sub.read())
        f_out.write(f_root.read())

    print("[PKI] PKI generada correctamente.")

def verify_full_pki():
    """verifica la coherencia completa de la pki"""

    print("[PKI] Verificando Root CA (autofirmada)...")
    subprocess.run([
        "openssl", "verify",
        "-CAfile", CA_ROOT_CRT,
        CA_ROOT_CRT
    ], check=True)

    print("[PKI] Verificando Sub CA contra Root CA...")
    subprocess.run([
        "openssl", "verify",
        "-CAfile", CA_ROOT_CRT,
        CA_SUB_CRT
    ], check=True)

    print("[PKI] Verificando certificado de AuthServer contra la cadena...")
    subprocess.run([
        "openssl", "verify",
        "-CAfile", CA_CHAIN,
        AUTH_CRT
    ], check=True)

    print("[PKI] Verificando certificado de BallotBox contra la cadena...")
    subprocess.run([
        "openssl", "verify",
        "-CAfile", CA_CHAIN,
        BALLOT_CRT
    ], check=True)

    print("[PKI] Todas las certificaciones de la PKI son válidas.")


def check_ca_private_keys(root_password: str, sub_password: str):
    # root
    with open(CA_ROOT_KEY, "rb") as f:
        serialization.load_pem_private_key(
            f.read(),
            password=root_password.encode()
        )
    # subroot
    with open(CA_SUB_KEY, "rb") as f:
        serialization.load_pem_private_key(
            f.read(),
            password=sub_password.encode()
        )



