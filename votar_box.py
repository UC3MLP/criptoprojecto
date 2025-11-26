import json
import base64
import sqlite3
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from db_utils import DB_PATH
from pki import (BALLOT_KEY_PATH, BALLOT_CERT_PATH, verify_with_openssl,
                 load_private_key, load_public_key)


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

    def __init__(self, auth_public_key:bytes, key_password: str):
        """ Incializa la urna con la clave publica de authserver
          key_password = passphrase usada en el openssl"""

        print("[BallotBox] Verificando certificado propio contra la PKI.")
        if not verify_with_openssl(BALLOT_CERT_PATH):
            raise RuntimeError("Certificado NO válido según la PKI.")

        print("[BallotBox] Cargando clave privada RSA de BallotBox.")
        self._priv = load_private_key(BALLOT_KEY_PATH, password=key_password)

        # clave pública desde el certificado
        self.public_key = load_public_key(BALLOT_CERT_PATH)

        # pública propia. para cifrar clave de sesión del voto
        self.pub_pem = self.public_key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

        print(f"[BallotBox] Clave RSA cargada.")


        print("[BallotBox] Iniciando Urna")
        self.auth_public_key = auth_public_key
        # Exportamos la pública para el cliente
        self.pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = self._priv.public_key()


    def verify_and_record(self, packet_json: str) -> bool:
        """recibe el paquete en json, lo descifra y devuelve T/F si lo
        acepta o no"""
        try:
            pkt = json.loads(packet_json)
            token = pkt["token"]

            try:
                raw_token =base64.urlsafe_b64decode(token)
                offset = 0

                #Extraer firma
                sig_len = 384
                if len(raw_token)< sig_len: return False
                signature = raw_token [offset: offset + sig_len]
                offset += sig_len


                #Extraer Hash del DNI
                dni_hash_bytes = raw_token[offset : offset +64]
                offset += 64

                #Extraer longitud del Election id
                election_id_len = int.from_bytes(raw_token[offset : offset +2], "big")
                offset += 2

                #Extraer election id
                election_id_bytes = (raw_token[offset : offset + election_id_len ])
                offset += election_id_len

                #Extraer Nonce 
                nonce = raw_token[offset:offset+16]
                offset+= 16

                #Extraer timestamp
                ts = raw_token[offset : offset + 8]

            except Exception as e:
                print(f"[BallotBox] Error leyendo el formato del token: {e}")
                return False
            

            #Verificación de la firma digital

            #Reconstruimos 

            #Dni_hash | election_id | nonce| ts

            print(f"Tipo dni_hash_bytes: {type(dni_hash_bytes)}")
            print(f"Tipo election_id_len: {type(election_id_bytes)}")
            print(f"Tipo election_id_bytes: {type(election_id_bytes)}")
            print(f"Tipo nonce: {type(nonce)}")
            print(f"Tipo ts: {type(ts)}")

            data_to_verify = dni_hash_bytes +b"|"+ election_id_bytes +b"|"+ nonce + b"|" + ts

            try:
                self.auth_public_key.verify(
                    signature,
                    data_to_verify,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length= padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("[BallotBox]Firma valida")
            except InvalidSignature:
                print("[BallotBox]Firma no valida")
                return False
            
            #Verificacion de repeticion en la base de datos

            token_hash_hex = hashlib.sha256(token.encode()).hexdigest()

            with sqlite3.connect(DB_PATH) as con:
                cur = con.cursor()
                row = cur.execute(
                    "SELECT used,election_id FROM tokens WHERE token_hash=?",
                    (token_hash_hex,)).fetchone()
                if not row :  # si no existe o usado, false
                    print("[BallotBox]Token valido pero no encontrado en la base de datos  ")
                    return False
                if  row[0] == 1:
                    print("[BallotBox]token ya usado ")
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
                    print("[BallotBox]padding o clave no valida")
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
                    print("[BallotBox] Inconsistencia: Token y Voto son para elecciones distintas.")
                    return False
                

                try :
                    #firma el voto para que no se pueda cambiar
                    vote_data = f"{vote['election_id']}|{vote['choice']}".encode('utf-8')
                    
                    signature = self._priv.sign(
                        vote_data,
                        padding.PSS( #Padding recomendado para firmas
                            mgf = padding.MGF1(hashes.SHA256()),
                            salt_length= padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    
                except Exception as e :
                    print( f"Error al firmar el voto: {e}")
                    return False #si no se puede firmar el voto, no se puede registrar
                

                cur.execute("UPDATE tokens SET used=1 WHERE token_hash=?", (token_hash_hex,))
                cur.execute("INSERT INTO tallies(election_id,choice_id, signature) VALUES(?,?,?)",
                            (vote["election_id"], vote["choice"], signature))
                con.commit()
                return True
            
        except Exception as e :
            print(f"[BallotBox] Error general: {e}")
            return False


    #Funcion de auditoria que revisa si los votos han sido modificados

    def audit_integrity(self)->bool:
        """ 
         Verifica la integridad de todos los votos en la tabla 'tallies' """
        
        try:
            with sqlite3.connect(DB_PATH) as con:
                cur = con.cursor()
                rows = cur. execute(
                    "SELECT election_id, choice_id, signature FROM tallies ORDER BY rowid"
                ).fetchall()

                if not rows:
                    print("Auditoría: No hay votos registrados")
                    return True
                for row in rows:
                    election_id, choice_id, signature = row

                    if not signature:
                        print(f"Error de auditoría: voto para {election_id} no tiene firma")
                        return False # Voto sin firma
                    
                    #reconstruir los datos exactamente como se firmaron
                    vote_data = f"{election_id}|{choice_id}".encode('utf-8')

                    try: 
                        self.public_key.verify(
                            signature,
                            vote_data,
                            padding.PSS( #mismo padding que al firmar
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length = padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                    except InvalidSignature :
                        print(f"Corrupción detectada, la firma del voto{election_id}='{choice_id}' Es inválida")
                        return False
                    
                    except Exception as e:
                        print( f"Error insesperado durante la verificación de la firma: {e}")
                        return False 
                    
                print(f"integridad de votos verificados")
                return True
        except sqlite3.Error as e:
            if "not such column : signature" in str(e):
                print("Error Auditoría: La tabla 'tallies' no tiene la columna 'signature")
                
            else:
                print(f"Errr de base de datos durnte la auditoría:{e}")
            return False
        except Exception as e:
            print(f"Error general en la auditoría: {e}")
            return False
            
                    
        

