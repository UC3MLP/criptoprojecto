import os
import tkinter as tk
from tkinter import ttk, messagebox
from db_utils import db_init
from auth_server import AuthServer, register_user, login_user
from votar_box import BallotBox
from crypto_client import ClientCrypto

# Inicializacion de tkinter


app = tk.Tk()

#dimensiones de el portal
app.geometry("300x300")
app.configure(background="white")
tk.Wm.wm_title(app,"sistema de autentificación")



tk.Button(
    app,
    text="iniciar",
    font=("courier",14),
    bg= "#00a8e8",
    fg="black",
).pack(
    fill=tk.BOTH,
    
)

app.mainloop()