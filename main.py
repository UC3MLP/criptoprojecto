import os
import sys
import logging
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox
from db_utils import db_init
from auth_server import AuthServer, register_user, login_user
from votar_box import BallotBox
from crypto_client import ClientCrypto

#Inicializacion y configuracion de logging para el archivo de logs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "registro_votacion.log")

logging.basicConfig(
    level= logging.INFO,
    format = "%(asctime)s [%levelname)s]%(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
# Inicializacion de tkinter

class App(ctk.CTk):
    def __init__(self,AuthServer,BallotBox,bb_pub_pem):
        super().__init__()
        self.auth_server = AuthServer # Guardamos la instancia del servidor de auteticación
        self.title("Sistema de votación - Acceso")
        self.geometry("500x500")
        self.ballot_box = BallotBox
        self.bb_pub_pem = bb_pub_pem
        

        #Crear tabView paera las pestañas
        self.tabview = ctk.CTkTabview(self, width =450,height = 350)
        self.tabview.pack(pady= 20, padx=20, fill ="both", expand =True)

        #crear pestañas
        self.tabview.add("Iniciar Sesión")
        self.tabview.add("Registrarse")

        #Etiqueta de estado
        self.status_label=ctk.CTkLabel(
            self,
            text= "",
            font = ("Arial",12,"bold"),
            text_color ="blue"
        )
        self.status_label.pack(pady=10)
        
        #Interfaces
        self.create_login_widgets(
        )
        self.create_register_widgets()

    def create_login_widgets(self):
        """widgets para login"""
        login_frame=self.tabview.tab("Iniciar Sesión")


        #mail
        ctk.CTkLabel(
            login_frame,
            text ="Email:",
            font =("Arial",13)).grid(row =0, column=0, sticky ='w',pady =10,padx=20)
        
        self.login_email_entry = ctk.CTkEntry(login_frame,width=250, placeholder_text="correo_ejemplo@gmail.com")

        self.login_email_entry.grid(row=0,column=1,pady=10,padx=10)

        #Contraseña
        ctk.CTkLabel(login_frame,text ="Contraseña:",  font =("Arial",13)).grid(row =1, column=0, sticky ='w',pady =10,padx=20)
        
        self.login_pwd_entry = ctk.CTkEntry(login_frame,width=250,show="*", placeholder_text="Contraseña")

        self.login_pwd_entry.grid(row=1,column=1,pady=10,padx=10) 

        #Boton para el Login
        ctk.CTkButton(login_frame, text = "Iniciar sesión", command =self.handle_login,
                      width=200, height=35, font=("Arial",13,"bold")).grid(row =2,column=0, columnspan=2, pady=30)

    def create_register_widgets(self):
        """widgets para register"""
        register_frame = self.tabview.tab("Registrarse")
        #etiquetas y campos de entrada
        #DNI
        ctk.CTkLabel(register_frame, text ="DNI:", font=('Arial',13)).grid(row=0,column =0,sticky='w', pady=10, padx=20)
        self.reg_dni_entry = ctk.CTkEntry(register_frame,width=250, placeholder_text="12345678A")
        self.reg_dni_entry.grid(row=0,column=1,pady=5,padx=5)

        #Email
        ctk.CTkLabel(register_frame, text ="Email:", font=('Arial',13)).grid(row=1,column =0,sticky='w', pady=10, padx=20)
        self.reg_email_entry = ctk.CTkEntry(register_frame,width=250, placeholder_text="correo@gmail.com")
        self.reg_email_entry.grid(row=1,column=1,pady=10,padx=10)

   
        #contraseña
        ctk.CTkLabel(register_frame, text ="Contraseña:", font=('Arial',13)).grid(row=2,column =0,sticky='w', pady=10, padx=20)
        self.reg_pwd_entry = ctk.CTkEntry(register_frame,width=250, show="*",placeholder_text="contraseña")
        self.reg_pwd_entry.grid(row=2,column=1,pady=10,padx=10)


         #Boton para el Registro
        ctk.CTkButton(register_frame, text = "Registrarse ", command =self.handle_register,width= 200, height=35,
                      font=("Arial",13,"bold")).grid(row =3,column=0, columnspan=2, pady=30)


    #register
    def handle_register(self):
        """lógica para registrarse"""
        dni = self.reg_dni_entry.get()
        email =self.reg_email_entry.get()
        password = self.reg_pwd_entry.get()

        #Limpiar el mensaje anterior si existe
        self.status_label.configure(text="")

        try:
            register_user(email,dni,password)
            self.status_label.configure(text="Registro completado, debes iniciar sesión",text_color="green")
            # si funciona, se sigue
            # Limpiar campos despues del registro
            self.reg_dni_entry.delete(0,tk.END)
            self.reg_email_entry.delete(0,tk.END)
            self.reg_pwd_entry.delete(0,tk.END)
            #Cambiar a la pestaña de login
            self.tabview.set("Iniciar Sesión")

        except ValueError as e:
            self.status_label.configure(text=f"Error de validación:{e}", text_color="red")
        except Exception as e:
            # Error de base de datos en caso de que existan por ejemplo ya el dni o el email
            if "UNIQUE constraint failed: users.dni" in str(e) :
                self.status_label.configure(text="Error Registro: DNI ya "
                                                 "está registrado", text_color="red")
            elif "UNIQUE constraint failed: users.email" in str(e) :
                self.status_label.configure(text="Error Registro: Email ya "
                                                 "está registrado", text_color="red")
            else:
                self.status_label.configure(text=f"Error :{e}", text_color="red")

    
    #login
    def handle_login(self):
        """lógica para el login"""
        email = self.login_email_entry.get()
        password = self.login_pwd_entry.get()

        # la función login _user de auth_server nos devuelve True o False y
        # el DNI asociado ya que es importante para después y para el database
        try:
            success, dni_user=login_user(email,password)
            if success:

                #Verificación de integridad
                is_integirty_ok = self.ballot_box.audit_integrity()
                if not is_integirty_ok:
                    print("Auditoría de integridad fallida, bloqueando votaciones")
          
                    self.status_label.configure(
                        text ="Error: los votos han sido manipulados.",
                        text_color = "red"
                    )

                    #popup de error
                    messagebox.showerror(
                        "Error Críticp de Integridad",
                        "No se puede continuar. La base de datos de votos(Urna) ha sido corrompida"
                    )
                    return
                #limpiamos campos de login
                self.login_email_entry.delete(0,tk.END)
                self.login_pwd_entry.delete(0,tk.END)
                #tras esto se llama a la siguiente ventana donde se realiza la votación
                self.show_law_selection(dni_user)
        except ValueError as e:
            self.status_label.configure(text =str(e),text_color='red')

        except Exception as e:
            self.status_label.configure(
                text = f"Error inesperado durante el login{e}",
                text_color = "red"
            )
            print(f"Eror inesperado en el handle_login{e}")

        
  #  Interfaz de votación

    def show_law_selection(self, dni):
        """Muestra la pantalla de selección de leyes"""
        self.withdraw() # Ocultar ventana principal

        try:
            selection_window = LawSelectionInterface(self, dni, self.auth_server, self.ballot_box, self.bb_pub_pem)
            self.wait_window(selection_window) # Esperar a que se cierre
        except Exception as e:
            print(f"Error en ventana de selección: {e}")
            messagebox.showerror("Error", f"Error al abrir selección de leyes: {e}")
        finally:
            self.deiconify() # Mostrar login al volver


class LawSelectionInterface(ctk.CTkToplevel):
    """Interfaz para seleccionar la ley a votar"""
    def __init__(self, master, dni, auth_server, ballot_box, bb_pub_pem):
        super().__init__(master)
        self.title("Selección de Ley")
        self.geometry("400x400")
        
        self.dni = dni
        self.auth_server = auth_server
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem
        
        ctk.CTkLabel(self, text="Seleccione una ley para votar:", font=("Arial", 16, "bold")).pack(pady=20)
        
        laws = {
            "Ley 1": "Ley 1",
            "Ley 2": "Propuesta de Ley 2",
            "Ley 3": "Propuesta de Ley 3"
        }
        
        for law_id, law_name in laws.items():
            # Frame para cada ley (Botón votar + Botón resultados)
            law_frame = ctk.CTkFrame(self)
            law_frame.pack(pady=5, padx=20, fill="x")
            
            ctk.CTkButton(law_frame, text=law_name, 
                          command=lambda l_id=law_id: self.open_voting(l_id),
                          width=200, height=40).pack(side="left", padx=10)
            
            ctk.CTkButton(law_frame, text="Ver Resultados",
                          command=lambda l_id=law_id: self.show_results(l_id),
                          width=120, height=40, fg_color="orange", hover_color="darkorange").pack(side="right", padx=10)

        # Botón de Cerrar Sesión
        ctk.CTkButton(self, text="Cerrar Sesión", command=self.destroy,
                      fg_color="red", hover_color="darkred", width=200, height=40).pack(pady=30)

    def show_results(self, law_id):
        """Muestra los resultados de la votación para una ley"""
        try:
            counts = self.ballot_box.get_vote_counts(law_id)
            msg = f"Resultados para {law_id}:\n\n" \
                  f"SI: {counts.get('SI', 0)}\n" \
                  f"NO: {counts.get('NO', 0)}\n" \
                  f"ABSTENCIÓN: {counts.get('ABSTENCIÓN', 0)}"
            messagebox.showinfo("Resultados", msg)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron obtener los resultados: {e}")

    def open_voting(self, law_id):
        """Abre la interfaz de votación para la ley seleccionada"""
        self.withdraw() # Ocultar selección
        try:
            voting_window = VotingInterface(self, self.dni, self.auth_server, self.ballot_box, self.bb_pub_pem, law_id)
            self.wait_window(voting_window) # Esperar a que termine de votar
            
            if hasattr(voting_window, 'logout_requested') and voting_window.logout_requested:
                self.destroy() # Si pidió logout, cerramos también esta ventana
            else:
                self.deiconify() # Si solo votó, volvemos a mostrar la selección
        except Exception as e:
            print(f"Error abriendo votación: {e}")
            self.deiconify()


class VotingInterface(ctk.CTkToplevel):
    """interfaz para la votación"""
    def __init__(self, master, dni, auth_server, ballot_box, bb_pub_pem, election_id):
        #tk.Toplevel crea una ventana secundaria
        super().__init__(master)
        self.title(f"Votación - {election_id}")
        self.geometry("550x450")

        #Datos y módulos clave
        self.dni = dni
        self.auth_server = auth_server
        self.election_id = election_id
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem
        self.logout_requested = False
        
        #Token de elegibilidad
        self.eligibility_token = None

        #título de la ley
        self.law_title_label= ctk.CTkLabel(self,text =f"Ley a votar: {self.election_id}",
                  font=('Arial',16,'bold'))
        self.law_title_label.pack(pady=10)
        
        #Etiqueta de estado
        self.status_label = ctk.CTkLabel(self,text="Seleccione su voto:",
                                         font=("Arial",12),text_color="white")
        self.status_label.pack(pady=10)


        self.crypto_client = ClientCrypto(bb_pub_pem)


        #Frame para los botones de votación
        button_frame = ctk.CTkFrame(self,fg_color="transparent")
        button_frame.pack(pady=30)

        #Botones de vot
        ctk.CTkButton(button_frame, text='Voto a favor', command= lambda: self.handle_vote("SI"), width=150, height=40,fg_color="green",
                   hover_color="darkgreen",font=("Arial",12,"bold")).pack(side=tk.LEFT, padx= 10)
        ctk.CTkButton(button_frame, text='Voto en contra', command= lambda: self.handle_vote("NO"), width=150, height=40,fg_color="red",
                   hover_color="darkred",font=("Arial",12,"bold")).pack(side=tk.LEFT, padx= 10)
        ctk.CTkButton(button_frame, text='Abstención', command= lambda: self.handle_vote("ABSTENCIÓN"), width=150, height=40,fg_color="gray",
                   hover_color="darkgray",font=("Arial",12,"bold")).pack(side=tk.LEFT, padx= 10)

        # Botón de Cerrar Sesión
        ctk.CTkButton(self, text="Cerrar Sesión", command=self.logout,
                      fg_color="red", hover_color="darkred", width=150, height=30).pack(side=tk.LEFT, padx=20, pady=20)

        # Botón de Volver
        ctk.CTkButton(self, text="Volver", command=self.go_back,
                      fg_color="gray", hover_color="darkgray", width=150, height=30).pack(side=tk.RIGHT, padx=20, pady=20)

    def go_back(self):
        """Cierra la ventana actual y vuelve a la selección"""
        self.destroy()

    def logout(self):
        self.logout_requested = True
        self.destroy()

    def get_eligibility_token(self):
        """Llama a AuthServer para obtener el token"""

        if self.eligibility_token:
            return True
        try:
            #comprobamos con authserver que el user no haya votado ya esa ley
            token = self.auth_server.issue_token(self.dni,self.election_id)

            self.eligibility_token = token

            #Actualizar a la ley actual
            self.law_title_label.configure (text= f"Ley Actual: {self.election_id}")
            self.status_label.configure(text= f"Token obtenido. DNI{self.dni [-4:]}...", text_color = "green")
            return True

        except ValueError as e:
            self.status_label.configure(text = f"ERROR: {e}", text_color= "red")
            messagebox.showerror("Error de Voto", str(e))
            return False
            
        #Para cualquier otro error
        except Exception as e:
            self.status_label.configure(text = f"ERROR AS : {e}", text_color= "red")
            messagebox.showerror("Error Crítico ",f"No se pudo obtener el token: {e}" )
            return False
  
        
    
    def handle_vote(self, vote_choice:str):
        """prepara el voto para llevarlo a la urna"""

         #iniciar el proceso de obtener el token y verificar
        if not self.get_eligibility_token():
            # Si falla al obtener token, no cerramos ventana, dejamos que el usuario vea el error o intente otra cosa (o salga)
            # Pero el código original hacía destroy(). Vamos a mantenerlo si es un error fatal, pero el token puede fallar por ya votado.
            # Si ya votó, quizás quiera salir.
            # Vamos a dejarlo como estaba: destroy() si falla token?
            # El original hacía destroy().
            return # No destruimos, dejamos que el usuario decida salir o cambiar ley (ahora salir)
        try: 
            vote_package_json = self.crypto_client.make_packet(
                self.election_id,
                vote_choice,
                self.eligibility_token)
        except Exception as e:
            messagebox.showerror("Error Criptográfico", f"Fallo al crear el paquete de voto cifrado: {e}")
            self.destroy()
            return
        
        try:
            success = self.ballot_box.verify_and_record(vote_package_json)
            if success:
                messagebox.showinfo("Voto Exitoso", "Su voto ha sido "
                                                    "registrado. Gracias por participar.")
            else:
                #si el token es invalido
                messagebox.showerror("Voto rechazado", f"voto rechazado por la Urna Electrónica (Fallo de seguridad/integridad)")
        except Exception as e :
            messagebox.showerror("Error de Urna", f"Fallo en la Urna al procesar el voto:{e}")
            success = False
        
        #Finalizar
        self.destroy() #Cerrar ventana de votación y volver a selección


if __name__ == "__main__":
    db_init()

    try:
        AUTH_KEY_PASSWORD = os.environ["AUTH_KEY_PASSWORD"]
        BALLOT_KEY_PASSWORD = os.environ["BALLOT_KEY_PASSWORD"]
        # hay que poner cuando se quiere ejecutar:
        # en macOS/Linux (Terminal):
        # export AUTH_KEY_PASSWORD="auth"
        # export BALLOT_KEY_PASSWORD="ballot"
        # python main.py
        #
        # en Windows (PowerShell):
        # $env:AUTH_KEY_PASSWORD="auth"
        # $env:BALLOT_KEY_PASSWORD="ballot"
        # python main.py
        #
        # en Windows (CMD):
        # set AUTH_KEY_PASSWORD=auth
        # set BALLOT_KEY_PASSWORD=ballot
        # python main.py
    except KeyError as e:
        missing = e.args[0]
        print(f"ERROR: falta la variable de entorno {missing}."
              f"Debes hacer 'export ...' antes de ejecutar")
        sys.exit(1)

    AS= AuthServer(key_password=AUTH_KEY_PASSWORD)
    BB = BallotBox(auth_public_key=AS.public_key,
                   key_password=BALLOT_KEY_PASSWORD)
    app = App(AS, BB, BB.pub_pem)
    app.mainloop()
