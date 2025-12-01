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
                
                # Recalcular cadena de hashes desde este punto
                self.recalculate_hashes(cur, token_hash_hex)

                cur.execute("INSERT INTO tallies(election_id,choice_id, signature) VALUES(?,?,?)",
                            (vote["election_id"], vote["choice"], signature))
                con.commit()
                return True
            
        except Exception as e :
            print(f"[BallotBox] Error general: {e}")
            return False

    def recalculate_hashes(self, cur, start_token_hash):
        """
        Recalcula los hashes de la cadena desde el token modificado hasta el final.
        Esto es necesario porque al cambiar 'used' de 0 a 1, el hash de esa fila cambia,
        y por tanto todos los siguientes también deben cambiar.
        """
        print(f"[BallotBox] Recalculando cadena de hashes desde {start_token_hash[:8]}...")
        
        # 1. Obtener el rowid del token modificado
        row = cur.execute("SELECT rowid FROM tokens WHERE token_hash=?", (start_token_hash,)).fetchone()
        if not row:
            return
        start_rowid = row[0]

        # 2. Obtener todos los tokens desde ese rowid en adelante (ordenados)
        tokens = cur.execute("""
            SELECT rowid, token_hash, election_id, used, dni 
            FROM tokens WHERE rowid >= ? ORDER BY rowid ASC
        """, (start_rowid,)).fetchall()

        # 3. Obtener el hash previo (del token justo antes del modificado)
        prev_row = cur.execute("SELECT chain_hash FROM tokens WHERE rowid < ? ORDER BY rowid DESC LIMIT 1", (start_rowid,)).fetchone()
        if prev_row:
            prev_hash = prev_row[0]
        else:
            prev_hash = "0" * 64 # Genesis

        # 4. Iterar y actualizar
        for t in tokens:
            t_rowid, t_hash, t_election, t_used, t_dni = t
            
            # Calcular nuevo hash
            chain_input = f"{prev_hash}{t_hash}{t_election}{t_used}{t_dni}".encode()
            new_chain_hash = hashlib.sha256(chain_input).hexdigest()

            # Actualizar en BD
            cur.execute("UPDATE tokens SET chain_hash=? WHERE rowid=?", (new_chain_hash, t_rowid))
            
            # El actual se convierte en el previo para el siguiente
            prev_hash = new_chain_hash
        
        print(f"[BallotBox] Cadena recalculada ({len(tokens)} tokens actualizados).")


    #Funcion de auditoria que revisa si los votos han sido modificados

    def audit_integrity(self)->bool:
        """ 
         Verifica la integridad de todos los votos en la tabla 'tallies' 
         Y TAMBIÉN la integridad de la cadena de tokens (Blockchain)
         asi no se puede cambiar ningún voto y los tokens están con un hash en cadena que no se puede modificar
        """
        
        try:
            with sqlite3.connect(DB_PATH) as con:
                cur = con.cursor()
                
                # Integridad de Votos (Firmas)
                rows = cur. execute(
                    "SELECT election_id, choice_id, signature FROM tallies ORDER BY rowid"
                ).fetchall()

                if not rows:
                    print("Auditoría: No hay votos registrados")
                else:
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
                
                print(f"Integridad de votos (firmas) verificada.")


                #  Integridad de Tokens (Hash Chain) 
                print("[Auditoría] Verificando cadena de bloques de tokens...")
                tokens = cur.execute("SELECT token_hash, election_id, used, dni, chain_hash FROM tokens ORDER BY rowid ASC").fetchall()
                
                prev_hash = "0" * 64 # Genesis
                
                for i, t in enumerate(tokens):
                    t_hash, t_election, t_used, t_dni, stored_chain_hash = t
                    
                    # Recalcular hash esperado
                    chain_input = f"{prev_hash}{t_hash}{t_election}{t_used}{t_dni}".encode()
                    calculated_hash = hashlib.sha256(chain_input).hexdigest()
                    
                    if calculated_hash != stored_chain_hash:
                        print(f"[Auditoría] ¡CORRUPCIÓN DETECTADA en Token #{i}!")
                        print(f"   Esperado: {calculated_hash}")
                        print(f"   Encontrado: {stored_chain_hash}")
                        return False
                    
                    prev_hash = calculated_hash # Avanzar

                print(f"[Auditoría] Cadena de tokens verificada correctamente ({len(tokens)} bloques).")
                return True

        except sqlite3.Error as e:
            if "not such column : signature" in str(e):
                print("Error Auditoría: La tabla 'tallies' no tiene la columna 'signature")
                
            else:
                print(f"Error de base de datos durnte la auditoría:{e}")
            return False
        except Exception as e:
            print(f"Error general en la auditoría: {e}")
            return False
            
                    
        


    def get_vote_counts(self, election_id: str) -> dict:
        """
       Esta funcion es para el conteo de votos, solo los cuenta y los printea, no hace nada mas
        """
        counts = {"SI": 0, "NO": 0, "ABSTENCIÓN": 0}
        try:
            with sqlite3.connect(DB_PATH) as con:
                cur = con.cursor()
                # Contar votos agrupados por choice_id
                rows = cur.execute(
                    "SELECT choice_id, COUNT(*) FROM tallies WHERE election_id=? GROUP BY choice_id",
                    (election_id,)
                ).fetchall()
                
                for choice, count in rows:
                    if choice in counts:
                        counts[choice] = count
                    else:
                        # Por si acaso hay algún voto con choice distinto (no debería)
                        counts[choice] = count
                        
        except Exception as e:
            print(f"[BallotBox] Error obteniendo conteo de votos: {e}")
            
        return counts
