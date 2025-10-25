import json
import base64
import sqlite3
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from db_utils import DB_PATH


def b64(b):
    """para el json"""
    return base64.urlsafe_b64encode(b).decode()


def ub64(s):
    """para el json"""
    return base64.urlsafe_b64decode(s.encode())


class BallotBox:
    """ 
    Clase que simula la urna electronica "BB" servidor de recepción de votos.
    """

    def __init__(self,issue_key:bytes):
        self.K_issue = issue_key  # misma clave compartida de AuthServer
        self._priv = rsa.generate_private_key(public_exponent=65537,
                                              key_size=3072)
        # clave PRIVADA! solo BB la conoce
        self.pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )  # clave PÚBLICA!

    def verify_and_record(self, packet_json: str) -> bool:
        """recibe el paquete en json, lo descifra y devuelve T/F si lo
        acepta o no"""
        try:
            pkt = json.loads(packet_json)
        except json.JSONDecodeError:
            return False

        token = pkt["token"]
        if not token:
            return False

        th = hashlib.sha256(token.encode()).hexdigest()  # guardo hash
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            row = cur.execute(
                "SELECT used,election_id FROM tokens WHERE token_hash=?",
                (th,)).fetchone()
            if not row or row[0] == 1:  # si no existe o usado, false
                return False
            election_id = row[1]  # si sí, recupero election_id. uso único!

            try:
                c_cifrada = ub64(pkt["clave_cifrada"])
                nonce = ub64(pkt["nonce"])
                ct = ub64(pkt["ct"])
                authenticated = pkt["authenticated"].encode()
            except (KeyError, binascii.Error, AttributeError):
                return False

            try:
                aes_key = self._priv.decrypt(
                    c_cifrada,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None)
                )  # descifro la clave pública con OAEP-SHA256
            except ValueError:
                # padding/clave incorrecta
                return False

            aesgcm = AESGCM(aes_key)
            try:
                plaintext = aesgcm.decrypt(nonce, ct, authenticated)
            except InvalidTag:
                # integridad fallida
                return False

            try:
                vote = json.loads(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # fallo de lodear json, o decode
                return False

            if vote.get("election_id") != election_id:
                # evitar que un token válido se use con otro ct
                return False

            cur.execute("UPDATE tokens SET used=1 WHERE token_hash=?", (th,))
            cur.execute("INSERT INTO tallies(election_id,choice) VALUES(?,?)",
                        (vote["election_id"], vote["choice"]))
            con.commit()
            return True

