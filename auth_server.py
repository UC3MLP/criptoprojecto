import os
import time
import hmac
import hashlib
import base64
import secrets
import sqlite3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import re
from db_utils import DB_PATH

# clave maestra para cifrar DNIS: ESTO NO TIENE QUE ESTAR EN EL CÓDIGO
# EN UN PROGRAMA REAL
DNI_ENCRYPTION_KEY = b"12345678901234567890123456789012"

# pbkdf2 = función criptográfica utilizada para derivar claves de contraseñas
# de forma segura
# DERIVACIÓN DE LA PBKDF2


def derive_pwd_hash(password, salt, iterations=200_000):
    """transforma contraseña en hash de 32 bytes con PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                         # tamaño normal
        salt= salt,
        iterations=200_000,
    )
    derive = kdf.derive(password.encode()) # pasando a bytes + derivando
    return derive

def dni_cifrar(dni_claro) -> str:
    """cifra el DNI con AES-GCM"""
    aesgcm = AESGCM(DNI_ENCRYPTION_KEY)
    nonce = secrets.token_bytes(12)  # 96 bits
    dni_bytes = dni_claro.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, dni_bytes, None)
    # nonce + ciphertext
    raw =nonce + ciphertext
    return base64.urlsafe_b64encode(raw).decode('ascii')

def dni_descifrar(encrypted_dni_b64: str) -> str:
    """descifra el DNI con AES-GCM"""
    try:
        raw = base64.urlsafe_b64decode(encrypted_dni_b64)
    except Exception as e:
        raise ValueError(f"DNI almacenado inválido (no base64): {e}")

    if len(raw) < 13:
        raise ValueError("DNI cifrado demasiado corto o corrupto.")
    aesgcm = AESGCM(DNI_ENCRYPTION_KEY)
    nonce = raw[:12]  # primeros 12 bytes
    ciphertext = raw[12:]  # resto
    try:
        dni_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("No se pudo descifrar el DNI: clave inválida o datos corruptos.")
    return dni_bytes.decode('utf-8')



def register_user(email, dni, password):
    """registro de usuario"""
    if not password :
        raise  ValueError("escribe una contraseña válida")
    if not re.match(r"^[A-Za-z0-9._%+-]+@gmail\.com$", email):
        # comprobar email - COMPROBACIÓN PUEDE QUE CAMBIE
        raise ValueError("Sólo se admite @gmail.com")
    if not re.match(r"^[0-9A-Z]{7,10}$", dni):
        # comprobar dni
        raise ValueError("DNI inválido.")
    salt = os.urandom(16)  # 128 bits aleatorios
    iterations = 200_000
    pwd_hash_password = derive_pwd_hash(password, salt, iterations)
    dni_cifrado_b64 = dni_cifrar(dni) #Dni cifrado que usaremos
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO users(email, dni, salt, pwd_hash, iterations) 
        VALUES (?,?,?,?,?)""",
                (email, dni_cifrado_b64, salt, pwd_hash_password, iterations))
    con.commit()
    con.close()


def login_user(email,password):
    """comprobar que tienen la misma contraseña"""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    row = cur.execute("""
        SELECT salt, pwd_hash, iterations , dni FROM users WHERE email=?
        """, (email,)).fetchone()
    con.close()
    # fetch la salt, pwd_hash y iterations
    if not row:
        # si no existe, nada
        raise ValueError("Email  no encontrado o incorrecto")

    salt, stored_hash, iterations, dni_cifrado_from_db = row  # la guardo
    test = derive_pwd_hash(password, salt, iterations)
    if not hmac.compare_digest(test, stored_hash):
        raise ValueError("Contraseña incorrecta")
    
    dni_claro = dni_descifrar(dni_cifrado_from_db)

    return True, dni_claro
    

        
    # si coinciden ? contraseña correcta y devuelve el dni asociado al correo 


# tokens de elegibilidad
class AuthServer:
    def __init__(self, issue_key: bytes):
        # issue_key = clave simétrica secreta compartida entre AS y BB.
        # mirar posibilidad de separar AS y BB, para que no compartan la clave
        self.K_issue = issue_key

    def issue_token(self, dni_claro, election_id):
        """generar un token (un solo uso) que permite a usuario votar sin
        revelar su identidad"""
        dni_cifrado = dni_cifrar(dni_claro)
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # usamos hash dni como índice
        dni_hash = hashlib.sha256(dni_claro.encode()).hexdigest()
        row = cur.execute("""
            SELECT token_hash, used FROM tokens WHERE dni=? AND 
            election_id=?""", (dni_hash, election_id)).fetchone()

        if row:
            # ya hay token emitido. no repetición!
            con.close()
            raise ValueError("No se permite votar dos veces.")

        # si no existe... uno nuevo
        nonce = secrets.token_bytes(16)
        ts = int(time.time()).to_bytes(8, "big")
        msg = (dni_claro.encode() + b"|" + election_id.encode() + b"|" + nonce +
               b"|" + ts)
        mac = hmac.new(self.K_issue, msg, hashlib.sha256).digest()
        # tag 32 bytes
        token = base64.urlsafe_b64encode(mac + nonce + ts).decode()
        # base64url( mac || nonce || ts
        th = hashlib.sha256(token.encode()).hexdigest()
        # hashear token codificado
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("""
            INSERT  INTO tokens(token_hash, election_id, 
            used,dni) VALUES (?, ?, ?,?)""", (th, election_id,0,  dni_hash))
        con.commit()
        con.close()
        return token
        # devuelve token entero 