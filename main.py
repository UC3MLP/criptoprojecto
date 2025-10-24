import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from db_utils import db_init
from auth_server import AuthServer, register_user, login_user
from votar_box import BallotBox
from crypto_client import ClientCrypto

# Inicializacion de tkinter

class App(tk.Tk):
    def __init__(self):

    def app(self):
        # NO ESTÁ HECHA!!!!
        app = tk.Tk()

        # dimensiones de el portal
        app.geometry("300x300")
        app.configure(background="white")
        tk.Wm.wm_title(app, "sistema de autentificación")

        tk.Button(
            app,
            text="iniciar",
            font=("courier", 14),
            bg="#00a8e8",
            fg="black",
        ).pack(
            fill=tk.BOTH,

        )

        app.mainloop()

if __name__ == "__main__":
    db_init()
    # Clave compartida AS/BB para HMAC de tokens (32 bytes)
    K_issue = os.urandom(32)
    AS = AuthServer(K_issue)
    BB = BallotBox(K_issue)
    app = App
    app.mainloop()
