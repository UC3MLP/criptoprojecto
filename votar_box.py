import json
import base64
import sqlite3
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
        pkt = json.loads(packet_json)
        token = pkt["token"]
        th = hashlib.sha256(token.encode()).hexdigest()  # guardo hash
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        row = cur.execute(
            "SELECT used,election_id FROM tokens WHERE token_hash=?",
            (th,)).fetchone()
        if not row or row[0] == 1:  # si no existe o usado, false
            con.close()
            return False
        election_id = row[1]  # si sí, recupero election_id. uso único!
        c_cifrada = ub64(pkt["clave_cifrada"])
        aes_key = self._priv.decrypt(
            c_cifrada,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )  # descifro la clave pública con OAEP-SHA256
        aesgcm = AESGCM(aes_key)
        nonce = ub64(pkt["nonce"])
        ct = ub64(pkt["ct"])
        authenticated = pkt["authenticated"].encode()
        try:
            vote = json.loads(aesgcm.decrypt(nonce, ct, authenticated).decode())
        except Exception:
            # si algún bit cambia, excepción
            con.close()
            return False
        if vote.get("election_id") != election_id:
            # evitar que un token válido se use con otro ct
            con.close()
            return False
        cur.execute("UPDATE tokens SET used=1 WHERE token_hash=?", (th,))
        cur.execute("INSERT INTO tallies(election_id,choice) VALUES(?,?)",
                    (vote["election_id"], vote["choice"]))
        con.commit()
        con.close()
        return True

