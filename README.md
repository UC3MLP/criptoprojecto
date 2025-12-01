#  Sistema de Votación Online Seguro
Este proyecto implementa un sistema de votación electrónica utilizando 
criptografía.
La interfaz gráfica ha sido desarrollada con **CustomTkinter**.

---
## Requisitos
Para ejecutar esta aplicación, necesitarás tener instalado:
1. **Python (cualquier versión superior o igual a la 3.8)**
2. Las dos librerías listadas a continuación.

---

### Librerías Necesarias

Las dos librerías externas son **CustomTkinter** (para la interfaz) y 
**Cryptography**  (para los algoritmos criptográficos como AES-GCM, 
RSA-OAEP, PBKDF2 y HMAC).

---

En caso de no tener **python 3.8 o superior** instalado:

En el terminal, ejecuta el siguiente comando:

```bash
pip install python3.14
```
O ve a la página principal de python **python.org/downloads** y sigue las 
instrucciones para instalarlo dependiendo de tu sistema operativo.

Para verificar la instalación puedes usar este comando en la terminal: 

```bash
pip python3 --version
```


Teniendo instalado python pondremos los siguientes comandos también en el 
terminal para instalar **customtkinter** y **cryptography**.

### Customtkinter
---

```bash
pip install customtkinter 

(En caso de estar en macOS: 
pip3 install customtkinter) 

````


Si ese comando no funciona, prueba usando este otro:
```bash
python3 -m pip install customtkinter 
```

### Cryptography
---
```bash
pip install  cryptography

(En caso de estar en macOS: 
pip3 install cryptography) 
````


Si ese comando no funciona, prueba usando este otro:
```bash
python3 -m pip install  cryptography
```


### CONTRASEÑAS:

para root (4096 bits pq es el estandar recomendado): root
para subroot (4096 bits): subroot
para auth: auth
para ballotbox: ballot

## Anexo 1: Claves estándar

Hemos llegado a un consenso sobre las claves que se utilizarían tanto 
para Root CA, Sub CA, AuthServer y BallotBox como para la clave de cifrado
del DNI. 

### Clave del DNI
Clave preferiblemente aleatoria, en base64 y AES. 
Se usa OpenSSL en la terminal, aplicando este comando:

```bash
openssl rand -base64 32
```

Entonces, obtendremos una clave adecuada para el DNI. 
Se añadirá a la terminal antes de ejecutar el archivo de esta manera:

**Windows (CMD):**
```cmd
set DNI_KEY={key}
python main.py
```

**Linux/Mac (Bash):**
```bash
DNI_KEY={key} python main.py
```

Si se nos olvida poner el DNI, hay una prompt que te preguntará por
la clave del DNI para ejecutar el programa.

**Clave de ejemplo:**
`KeEn6FVMn26JTAPDBvR/mFm5kufFmnL2r3mZUsR5BIg=`

## Anexo 2: Requisitos Previos (OpenSSL)

Es necesario tener instalado **OpenSSL** en el sistema operativo.

### Verificación
Para comprobar si está instalado, ejecuta:

```bash
openssl version
```

Si el comando funciona, el entorno está listo.

### Configuración en Windows
Para evitar crear esto, se ha definido openssl.cnf. 
Si esto no funciona, hay que definir la variable de entorno:

```cmd
setx OPENSSL_CONF "C:\Program Files\OpenSSL-Win64\ssl\openssl.cnf"
```

> **Nota:** Reinicia la terminal después de configurar la variable de entorno.
