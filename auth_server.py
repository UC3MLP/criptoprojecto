import os
import time
import hmac
import hashlib
import base64
import secrets
import sqlite3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import re
from db_utils import DB_PATH
from pki import (AUTH_KEY_PATH, AUTH_CERT_PATH, verify_with_openssl,
                 load_private_key, load_public_key)

# clave maestra para cifrar DNIS: ESTO NO TIENE QUE ESTAR EN EL CÓDIGO
# EN UN PROGRAMA REAL
DNI_ENCRYPTION_KEY = b"12345678901234567890123456789012"

# pbkdf2 = función criptográfica utilizada para derivar claves de contraseñas
# de forma segura
# DERIVACIÓN DE LA PBKDF2
def derive_pwd_hash(password, salt, iterations=200_000):
    """transforma la contraseña en hash de 32 bytes con PBKDF2"""
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
    """ Servidor de utenticación que emite tokens firmados con RSA """
    def __init__(self, key_password: str):
        """ Genera claves RSA en memoria(volátiles)(HAY QUE CAMBIARLO PARA QUE LAS CLAVES SE GUARDEN EN EL DISCO)
        key_password = passphrase usada en el openssl"""

        print("[AuthServer] Verificando certificado propio contra la PKI.")
        if not verify_with_openssl(AUTH_CERT_PATH):
            raise RuntimeError("Certificado NO válido según la PKI.")

        print("[AuthServer] Cargando clave privada RSA desde disco.")
        self._priv_key = load_private_key(AUTH_KEY_PATH, password=key_password)
        # ahora, la clave pública desde certificado
        self.public_key = load_public_key(AUTH_CERT_PATH)

        # exportar la pública para ir a ballotbox
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        print(f"[AuthServer] Clave RSA cargada.")

    def issue_token(self, dni_claro, election_id):
        """generar un token (un solo uso) que permite a usuario votar sin
        revelar su identidad"""
        con = sqlite3.connect(DB_PATH, timeout=10)
        cur = con.cursor()
        # usamos hash dni como índice
        dni_hash = hashlib.sha256(dni_claro.encode()).hexdigest()
        row = cur.execute("""
            SELECT token_hash, used FROM tokens WHERE dni=? AND 
            election_id=?""", (dni_hash, election_id)).fetchone()

        if row:
            token_hash_db, used_db = row
            if used_db == 1:
                # ya hay token emitido. no repetición!
                con.close()
                print(f"[AuthServer] el Usuario ya gasto su voto")
                raise ValueError("No se permite votar dos veces.")
            else:
                print(f"usuario tenia el token sin usar, re emitiendo")

                cur.execute("DELETE FROM tokens WHERE token_hash=?", (token_hash_db,))

        # si no existe... uno nuevo

        #Creamos componentes del token
        nonce = secrets.token_bytes(16)
        ts = int(time.time()).to_bytes(8, "big")



        #Construimos el mensaje a firmar
        #Formato : dni_hash || election_id || nonce || timestamp
        election_id_bytes = election_id.encode('utf-8')
        #Guardamos la longitud del id para desempaquetarlo luego 
        election_id_len = len(election_id_bytes).to_bytes(2,"big")

        data_to_sign = (
            dni_hash.encode('utf-8')+ b"|"+
            election_id_bytes + b"|"+
            nonce + b"|"+
            ts
        )




        #Firma con RSA-PSS
        signature = self._priv_key.sign(
            data_to_sign,
            padding.PSS(
                mgf= padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        
        #Empaquetamos el token
        #El token es igual a firma||dni_hash||election_id_len(2)||election_id||nonce||ts
        token_bytes = (
            signature+
            dni_hash.encode('utf-8')+
            election_id_len +
            election_id_bytes +
            nonce +
            ts

        )

        # tag 32 bytes
        token_b64 = base64.urlsafe_b64encode(token_bytes).decode()


        #Guardamos el hash del token en BD
        token_hash= hashlib.sha256(token_b64.encode()).hexdigest()
        

        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("""
            INSERT  INTO tokens(token_hash, election_id, 
            used,dni) VALUES (?, ?, ?,?)""", (token_hash, election_id,0,  dni_hash))
        con.commit()
        con.close()
        print(f"[AuthServer] Token firmado emitido para ...{dni_claro[-4:]}")
        return token_b64
        # devuelve token entero 