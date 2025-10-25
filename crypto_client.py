import os
import json
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(b):
    """para meter en un json"""
    return base64.urlsafe_b64encode(b).decode()


class ClientCrypto:
    """clase que se encarga de cifrar el paquete para ser enviado a
    votar_box y descifrado"""
    def __init__(self, bb_pub_pem: bytes):
        # clave pública de ballotbox (NUNCA PRIVADA!)
        self.pub = serialization.load_pem_public_key(bb_pub_pem)

    def make_packet(self, election_id: str, choice: str, token: str) -> str:
        """preparar paquete de voto para enviar a ballotbox"""
        aes_key = AESGCM.generate_key(bit_length=256)  # AES-256 aleatoria
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)  # 96 bits - único por cada clave
        authenticated = f"vote:{election_id}".encode()  # atar cifrado a elección
        payload = json.dumps({  # lo que sí se cifra
            "election_id": election_id,
            "choice": choice,
            "client_nonce": b64(secrets.token_bytes(16))
        }).encode()
        ct = aesgcm.encrypt(nonce, payload, authenticated)
        # GCM:conf+integridad
        # ct = ciphertext+tag

        # RSA-OAEP
        c_cifrada = self.pub.encrypt(aes_key,
                              padding.OAEP(
                                  mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                  algorithm=hashes.SHA256(), label=None))
        # json
        pkt = {"clave_cifrada": b64(c_cifrada),  # clave simétrica con RSA-OAEP
               "nonce": b64(nonce),  # nonce de AES-GCM
               "ct": b64(ct),  # ciphertext || tag
               "authenticated": authenticated.decode(),
               # autenticado ("vote:<id>")
               "token": token}  # token de 1 solo uso
        return json.dumps(pkt)
