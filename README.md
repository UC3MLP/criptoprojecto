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


### Cambios :

Clave DNI Hardcodeada: DNI_ENCRYPTION_KEY está escrita en el código (1234...). Debería cargarse de variable de entorno o fichero seguro.

Hacer que nadie se pueda meter a cambiar el used a 0 o a 1 generando el hash del ultimo voto con el anterior