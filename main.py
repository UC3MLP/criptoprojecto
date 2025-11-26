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
logging.basicConfig(
    level= logging.INFO,
    format = "%(asctime)s [%levelname)s]%(message)s",
    handlers=[
        logging.FileHandler("registro_votacion.log"),
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
                self.show_voting_interface(dni_user)
        except ValueError as e:
            self.status_label.configure(text =str(e),text_color='red')

        except Exception as e:
            self.status_label.configure(
                text = f"Error inesperado durante el login{e}",
                text_color = "red"
            )
            print(f"Eror inesperado en el handle_login{e}")

        
  #  Interfaz de votación

    def show_voting_interface(self,dni):
        """plataforma de votación"""
        self.withdraw() #ocultamos la ventana principal

        try:
            #Abre la nueva ventana 
            Voting_window = VotingInterface(self,dni,self.auth_server,self.ballot_box, self.bb_pub_pem)

            self.wait_window(Voting_window) #Bloquea la ventana hasta que termine el voto
        except Exception as e:
            print(f"Error en ventana de votación {e}")
            messagebox.showerror("Error", f"Error al abrir ventana de votación {e}")

        finally:
            #despues de votar te lleva a login de nuevo
            self.deiconify()


class VotingInterface(ctk.CTkToplevel):
    """interfaz para la votación"""
    def __init__(self, master,dni,auth_server, ballot_box, bb_pub_pem):
        #tk.Toplevel crea una ventana secundaria
        super().__init__(master)
        self.title("Plataforma de votación")
        self.geometry("550x400")

        #Datos y módulos clave
        self.dni = dni
        self.auth_server = auth_server
        self.election_id = "Ley 1"
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem
        
        #Token de elegibilidad
        self.eligibility_token = None

        #título de la ley
        self.law_title_label= ctk.CTkLabel(self,text =f"Ley a votar:{self.election_id}",
                  font=('Arial',16,'bold'))
        self.law_title_label.pack(pady=10)
        

        #Boton para cambiar de ley
        ctk.CTkButton(self, text = 'Cambiar ley',command=self.show_election_selector, width =150,
                      height=30).pack(pady=10)

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

       

    def show_election_selector(self):
        """Muestra una ventana para elegir una nueva ley y reiniciar la
        votación"""
        laws= {"Ley 1": " Ley 1",
               "Ley 2":" Propuesta de Ley 2",
               "Ley 3": " Propuesta de Ley 3"
               }
        
        #configuración de la ventana de selección
        selector_window = ctk.CTkToplevel(self)
        selector_window.title("Seleccionar Ley")
        selector_window.geometry("350x300")
        selector_window.transient(self)#hace que la ventana este arriba siempre

        ctk.CTkLabel(selector_window, text = "Elige la Ley para la que quieres votar",
                     font=("Arial",13,"bold")).pack(padx=20,pady=20)

            #Gestor de la selección
        def select_law(law_id, law_name):
            #Cierra la ventana de selección anterior
            selector_window.destroy()
            self.election_id = law_id
            self.law_title_label.configure(text= f"Ley a votar: {self.election_id}")
            self.status_label.configure(text = f"Cambio a :{law_name}",text_color= "white")

            #Limpia el token anterior y reinicia el proceso de elegibilidad
            self.eligibility_token = None 
            #Botones para cada ley
        for law_name, law_id in laws.items():
            ctk.CTkButton(selector_window,text = law_name,
                    command=lambda l_id=law_id,
                    l_name=law_name:select_law(l_id,l_name),
                    width=250, height=35).pack(pady =10, padx=20)

    
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
            self.destroy()
            return
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
        self.destroy() #Cerrar ventana de votación


if __name__ == "__main__":
    db_init()

    try:
        AUTH_KEY_PASSWORD = os.environ["AUTH_KEY_PASSWORD"]
        BALLOT_KEY_PASSWORD = os.environ["BALLOT_KEY_PASSWORD"]
        # hay que poner cuando se quiere ejecutar:
        # en powershell
        # $env:AUTH_KEY_PASSWORD="auth"
        # $env:BALLOT_KEY_PASSWORD="ballot"
        # en cmd
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
