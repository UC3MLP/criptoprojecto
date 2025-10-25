import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils




class ClientCrypto:
    """ 
    gestion de claves asimetricas y firma digital para el votante
    """
    
    def __init__(self):
        #el cliente genera un par de claves(privada para firmar, pública para verificar)
        self.private_key = self._generate_private_key()
        self.public_key = self.private_key.public_key()

    def _generate_private_key(self):
        """ Genera clave privada RSA para la firma(2048bits) """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size= 2048
        )
    
    def generate_aes_key(self)-> bytes:
        """ genera clave AES de 256 bits """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return os.urandom(32)
    
    def encrypt_vote_aes(self,vote_choice: str,aes_key:bytes)-> tuple:
        """ cifra el voto   """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = os.urandom(12)#96 bits para gcm
        aesgcm = AESGCM(aes_key)
        encrypted = aesgcm.encrypt(iv, vote_choice.encode('utf-8'),None)

        #retornar iv y voto cifrado en base 64
        return(base64.urlsafe_b64encode(iv).decode('utf-8'),
       base64.urlsafe_b64encode(encrypted).decode('utf-8')) 