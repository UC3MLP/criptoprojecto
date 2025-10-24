import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from db_utils import db_init
from auth_server import AuthServer, register_user, login_user
from votar_box import BallotBox
"from crypto_client import ClientCrypto"

# Inicializacion de tkinter

class App(tk.Tk):
    def __init__(self,AuthServer):
        super().__init__()
        self.auth_server = AuthServer # Guardamos la instancia del servidor de auteticación
        self.title("sistema de votación-Acceso")
        self.geometry("400x350")
        self.configure(background="#f0f0f0")

    
         #estilo para los widgets
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TNotebook.Tab',font =('Arial',10,'bold'))
        style.configure('TButton',font=('Arial',10),padding = 6)


        #contenedor de pestañas(Notebook)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, expand=True, fill ="both")

        #Frames para pestañas
        self.login_frame = ttk.Frame(self.notebook,padding ="10 10 10 10 ")
        self.register_frame = ttk.Frame(self.notebook,padding = "10 10 10 10 ")
        self.notebook.add(self.login_frame,text= "Iniciar Sesión")
        self.notebook.add(self.register_frame,text= "Registrarse")
        self.create_login_widgets()
        self.create_register_widgets()

    #widgets de inicio de sesion 
    def create_login_widgets(self):
        #etiquetas y campos de entrada
        
        ttk.Label(self.login_frame, text ="Email:", font=('Arial',10)).grid(row=0,column =0,sticky='w', pady=5)
        self.login_email_entry = ttk.Entry(self.login_frame,width=30)
        self.login_email_entry.grid(row=0,column=1,pady=5,padx=5)

        ttk.Label(self.login_frame, text ="Contraseña:", font=('Arial',10)).grid(row=2,column =0,sticky='w', pady=5)
        self.login_pwd_entry = ttk.Entry(self.login_frame,width=30)
        self.login_pwd_entry.grid(row=2,column=1,pady=5,padx=5)


        #Boton para el Login
        ttk.Button(self.login_frame, text = "Iniciar sesión", command =self.handle_login).grid(row =3,column=0, columnspan=2, pady=20)

    def create_register_widgets(self):

        #etiquetas y campos de entrada
        ttk.Label(self.register_frame, text ="DNI:", font=('Arial',10)).grid(row=0,column =0,sticky='w', pady=5)
        self.reg_dni_entry = ttk.Entry(self.register_frame,width=30)
        self.reg_dni_entry.grid(row=0,column=1,pady=5,padx=5)


        ttk.Label(self.register_frame, text ="Email:", font=('Arial',10)).grid(row=1,column =0,sticky='w', pady=5)
        self.reg_email_entry = ttk.Entry(self.register_frame,width=30)
        self.reg_email_entry.grid(row=1,column=1,pady=5,padx=5)

        ttk.Label(self.register_frame, text ="Contraseña:", font=('Arial',10)).grid(row=2,column =0,sticky='w', pady=5)
        self.reg_pwd_entry = ttk.Entry(self.register_frame, show="*", width=30)
        self.reg_pwd_entry.grid(row=2,column=1,pady=5,padx=5)

         #Boton para el Registro
        ttk.Button(self.register_frame, text = "Registrarse ", command =self.handle_register).grid(row =3,column=0, columnspan=2, pady=20)


    #lógica para el register
    def handle_register(self):
        dni = self.reg_dni_entry.get()
        email =self.reg_email_entry.get()
        password = self.reg_pwd_entry.get()

        try:
            register_user(email,dni,password)
            messagebox.showinfo("Registro completado, Inicia sesión")
            # Limpiar campos despues del registro
            self.reg_dni_entry.delete(0,tk.END)
            self.reg_email_entry.delete(0,tk.END)
            self.reg_pwd_entry.delete(0,tk.END)
            #Cambiar a la pestaña de login
            self.notebook.select(self.login_frame)

        except ValueError as e:
            messagebox.showerror("Error de Validación",str(e))
        except Exception as e:
            # Error de base de datos en caso de que existan por ejemplo ya el dni o el email
            if "UNIQUE constrait failed" in str(e):
                messagebox.showerror("Ya hay un email o DNI registrado")
            else:
                messagebox.showerror("Error desconocido")

    
    #Lógica para el login
    def handle_login(self):
        email = self.login_email_entry.get()
        password = self.login_pwd_entry.get()

        #la función login _user de auth_server nos devuelve true o false

        if login_user(email,password):
            messagebox.showinfo("Sesión iniciada",)
            #tras esto se llama a la siguiente ventana donde se realiza la votación
            self.show_voting_interface()
        else:
            messagebox.showerror("Error,Dni,Email o contraseña incorrectos")


    
    #  Interfaz de votación

    def show_voting_interface(self):
        #plataforma de votacion
        #por ahora cerrada falta por hacer!!!!!
        self.destroy()

        #se necesita abrir la ventana principal para dejar al usuario
        # las opciones
        print(f"Usuario ha iniciado sesión")



        






if __name__ == "__main__":
    db_init()
    # Clave compartida AS/BB para HMAC de tokens (32 bytes)
    K_issue = os.urandom(32)
    AS = AuthServer(K_issue)
    BB = BallotBox(K_issue)
    app = App(AS)
    app.mainloop()
