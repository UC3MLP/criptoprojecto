import os
import sys
import json
import logging
import getpass
import subprocess
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox
from db_utils import db_init
from auth_server import AuthServer, register_user, login_user
from votar_box import BallotBox
from crypto_client import ClientCrypto
from pki import generating_pki, verify_full_pki, check_ca_private_keys
from datetime import date, timedelta

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
        self.geometry("500x500")
        
        self.dni = dni
        self.auth_server = auth_server
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem

        # primer domingo de 2025: 5 enero 2025
        self.current_date = date(2025, 1, 5)
        self.current_week = 0
        
        ctk.CTkLabel(self, text="Leyes", font=("Arial", 16, "bold")).pack(pady=20)

        try:
            with open("laws.json", "r", encoding="utf-8") as f:
                self.all_laws = json.load(f)
        except Exception as e:
            print(f"Error cargando leyes: {e}")
            messagebox.showerror("Error",
                                 f"No se pudieron cargar las leyes: {e}")
            self.all_laws = []

            # leyes: revelar, activas y caducadas
            # hacemos copia para poder añadir metadata (reveal_week)
        self.pending_laws = [dict(law) for law in self.all_laws]
        self.active_laws = []  # leyes ya reveladas y aún dentro de plazo
        self.expired_laws = set()  # ids de leyes caducadas

        # ley actual
        self.current_law = None

        # título
        ctk.CTkLabel(
            self,
            text="Seleccione una ley activa:",
            font=("Arial", 14, "bold")
        ).pack(pady=10)

        # debug, ir siguiente domingo
        debug_frame = ctk.CTkFrame(self)
        debug_frame.pack(pady=5, padx=10, fill="x")

        self.date_label = ctk.CTkLabel(
            debug_frame,
            text="",
            font=("Arial", 12)
        )
        self.date_label.pack(side="left", padx=10)

        self.next_sunday_button = ctk.CTkButton(
            debug_frame,
            text="Ir al siguiente domingo",
            command=self.go_to_next_sunday,
            width=180,
            height=28,
            font=("Arial", 11)
        )
        self.next_sunday_button.pack(side="right", padx=10)

        # scrollable frame para las leyes activas
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=550,
                                                       height=400)
        self.scrollable_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # cerrar sesión
        ctk.CTkButton(
            self,
            text="Cerrar Sesión",
            command=self.destroy,
            fg_color="red",
            hover_color="darkred",
            width=200,
            height=40
        ).pack(pady=15)

        # estado inicial inicializado
        self._activate_next_law_if_available()
        self._update_date_label()
        self.render_laws()

        # métodos para tiempo y leyes !

    def _update_date_label(self):
        """actualiza la etiqueta de la fecha simulada"""
        self.date_label.configure(
            text=f"Hoy: {self.current_date.strftime('%d/%m/%Y')}"
        )

    def _activate_next_law_if_available(self):
        """saca la siguiente ley de pending_laws y la hace activa
        en la semana actual"""
        if self.pending_laws:
            next_law = self.pending_laws.pop(0)
            # guardamos en qué semana se reveló
            next_law["reveal_week"] = self.current_week
            self.active_laws.append(next_law)
        else:
            # no hay más leyes nuevas por revelar
            # desactivamos el botón
            if not self.active_laws:
                self.next_sunday_button.configure(state="disabled")

    def _expire_old_laws(self):
        """marca como caducadas las leyes con 4 o más domingos de antigüedad"""
        still_active = []
        for law in self.active_laws:
            reveal_week = law.get("reveal_week", 0)
            age_weeks = self.current_week - reveal_week
            if age_weeks >= 4:
                # caducada
                self.expired_laws.add(law["id"])
            else:
                still_active.append(law)
        self.active_laws = still_active

    def go_to_next_sunday(self):
        """avanza una semana en el tiempo simulado y actualiza las leyes"""
        self.current_week += 1
        self.current_date = self.current_date + timedelta(days=7)
        self._update_date_label()

        # caducar leyes antiguas y revelar nueva si queda
        self._expire_old_laws()
        self._activate_next_law_if_available()
        self.render_laws()

        # leyes

    def render_laws(self):
        """redibuja la lista de leyes activas y no caducadas"""
        # Borrar todo lo que haya en el scrollable_frame
        for child in self.scrollable_frame.winfo_children():
            child.destroy()

        if not self.active_laws:
            ctk.CTkLabel(
                self.scrollable_frame,
                text="No hay leyes activas en este momento.\n"
                     "Avanza al siguiente domingo para revelar nuevas leyes\n"
                     "o todas las leyes han caducado.",
                font=("Arial", 13)
            ).pack(pady=20)
            return

        # leyes ya votadas por este DNI
        already_voted = self.auth_server.get_voted_elections(self.dni)

        for law in self.active_laws:
            law_id = law["id"]
            law_title = law["title"]
            law_desc = law["description"]

            if law_id in self.expired_laws:
                # seguridad
                continue

            # frame para cada ley activa
            law_frame = ctk.CTkFrame(self.scrollable_frame)
            law_frame.pack(pady=5, padx=5, fill="x")

            # Título
            ctk.CTkLabel(
                law_frame,
                text=f"{law_id}: {law_title}",
                font=("Arial", 12, "bold")
            ).pack(anchor="w", padx=10, pady=(5, 0))

            # Descripción
            ctk.CTkLabel(
                law_frame,
                text=law_desc,
                font=("Arial", 13),
                wraplength=480,
                justify="left",
                anchor="w"
            ).pack(fill="x", padx=10, pady=(0, 5))

            # Botones
            btn_frame = ctk.CTkFrame(law_frame, fg_color="transparent")
            btn_frame.pack(fill="x", pady=5)

            # Botón de Votar
            if law_id not in already_voted:
                ctk.CTkButton(
                    btn_frame,
                    text="Votar",
                    command=lambda l=law: self.open_voting(l),
                    width=100, height=30
                ).pack(side="left", padx=10)
            else:
                ctk.CTkLabel(
                    btn_frame,
                    text="Ya has votado esta ley.",
                    font=("Arial", 10),
                    text_color="gray"
                ).pack(side="left", padx=10)

            # Botón de Resultados
            ctk.CTkButton(
                btn_frame,
                text="Resultados",
                command=lambda l_id=law_id: self.show_results(l_id),
                width=120, height=30,
                fg_color="orange",
                hover_color="darkorange"
            ).pack(side="right", padx=10)

        # resultados

    def show_results(self, law_id):
        """muestra los resultados de la votación para una ley"""
        try:
            counts = self.ballot_box.get_vote_counts(law_id)
            msg = (
                f"Resultados para {law_id}:\n\n"
                f"SI: {counts.get('SI', 0)}\n"
                f"NO: {counts.get('NO', 0)}\n"
                f"ABSTENCIÓN: {counts.get('ABSTENCIÓN', 0)}"
            )
            messagebox.showinfo("Resultados", msg)
        except Exception as e:
            messagebox.showerror("Error",
                                 f"No se pudieron obtener los resultados: {e}")

    def open_voting(self, law_data):
        """abre la interfaz de votación para la ley seleccionada"""
        self.withdraw()  # Ocultar selección
        try:
            voting_window = VotingInterface(
                self,
                self.dni,
                self.auth_server,
                self.ballot_box,
                self.bb_pub_pem,
                law_data
            )
            self.wait_window(voting_window)  # esperar a que termine de votar

            # tras cerrar la ventana de voto, volvemos a mostrar selección
            if hasattr(voting_window,
                       'logout_requested') and voting_window.logout_requested:
                self.destroy()  # logout → cerrar también esta ventana
            else:
                self.deiconify()
                # puede que esta ley ya haya sido votada → refrescar listado
                self.render_laws()
        except Exception as e:
            print(f"Error abriendo votación: {e}")
            self.deiconify()


class VotingInterface(ctk.CTkToplevel):
    """interfaz para la votación"""
    def __init__(self, master, dni, auth_server, ballot_box, bb_pub_pem, law_data):
        #tk.Toplevel crea una ventana secundaria
        super().__init__(master)
        
        self.law_id = law_data["id"]
        self.law_title = law_data["title"]
        self.law_description = law_data["description"]
        
        self.title(f"Votación - {self.law_title}")
        self.geometry("600x550") # Un poco más grande para la descripción

        #Datos y módulos clave
        self.dni = dni
        self.auth_server = auth_server
        self.election_id = self.law_id # Usamos el ID como election_id
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem
        self.logout_requested = False
        
        #Token de elegibilidad
        self.eligibility_token = None

        #título de la ley
        self.law_title_label= ctk.CTkLabel(self,text =f"{self.law_id}: {self.law_title}",
                  font=('Arial',18,'bold'), wraplength=550)
        self.law_title_label.pack(pady=(20, 10))
        
        # Descripción de la ley
        self.desc_textbox = ctk.CTkTextbox(self, width=500, height=100, font=("Arial", 14))
        self.desc_textbox.insert("0.0", self.law_description)
        self.desc_textbox.configure(state="disabled") # Solo lectura
        self.desc_textbox.pack(pady=10)
        
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

    print("¡Inicialización de la PKI!\n")
    print("Si es la primera vez, se generarán las claves/certificados en "
          "la carpeta 'keys/'.")
    print("Las claves privadas que hemos decidido usar están en el README.\n")

    # se piden las contraseñas
    try:
        root_password = getpass.getpass("Password para root: ")
        sub_password = getpass.getpass("Password para subroot: ")
        auth_password = getpass.getpass(
            "Password para AuthServer: ")
        ballot_password = getpass.getpass(
            "Password para BallotBox: ")
    except KeyboardInterrupt:
        print("\nCancelado por el usuario.")
        sys.exit(1)

    # pki se genera si es que no existe
    try:
        generating_pki(root_password, sub_password, auth_password,
                       ballot_password)
        check_ca_private_keys(root_password, sub_password)
        verify_full_pki()
    except subprocess.CalledProcessError as e:
        print("\nERROR generando la PKI con OpenSSL.")
        print("Comando falló con código:", e.returncode)
        sys.exit(1)

    # creamos authserver, ballotbox
    try:
        AS = AuthServer(key_password=auth_password)
    except Exception as e:
        print(f"\nERROR inicializando AuthServer: {e}")
        sys.exit(1)

    try:
        BB = BallotBox(
            auth_public_key=AS.public_key,
            key_password=ballot_password,
        )
    except Exception as e:
        print(f"\nERROR inicializando BallotBox: {e}")
        sys.exit(1)

# siempre pon: set DNI_KEY={llave en base 64 de 32}

    app = App(AS, BB, BB.pub_pem)
    app.mainloop()
