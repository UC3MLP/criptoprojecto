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
    def __init__(self,AuthServer,BallotBox,bb_pub_pem):
        super().__init__()
        self.auth_server = AuthServer # Guardamos la instancia del servidor de auteticación
        self.title("sistema de votación-Acceso")
        self.geometry("400x350")
        self.ballot_box = BallotBox
        self.bb_pub_pem = bb_pub_pem
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
        
        #etiqueta de estado para mensajes del sistema
        self.status_label =ttk.Label(self,text="", font=('Arial',10,'bold'))
        self.status_label.pack(pady= 5)

        #Creando las interfaces
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

        #Limpiar el mensaje anterior si existe
        self.status_label.config(text="")

        try:
            register_user(email,dni,password)
            self.status_label.config(text="Registro completado, debes iniciar sesión",foreground="blue")
            # Limpiar campos despues del registro
            self.reg_dni_entry.delete(0,tk.END)
            self.reg_email_entry.delete(0,tk.END)
            self.reg_pwd_entry.delete(0,tk.END)
            #Cambiar a la pestaña de login
            self.notebook.select(self.login_frame)

        except ValueError as e:
            self.status_label.config(text=f"Error de validadción:{e}", foreground="red")
        except Exception as e:
            # Error de base de datos en caso de que existan por ejemplo ya el dni o el email
            if "UNIQUE constrait failed" in str(e):
                self.status_label.config(text="Error Registro DNI o Email ya está registrado", foreground="red")
            else:
                self.status_label.config(text=f"Error :{e}", foreground="red")

    
    #Lógica para el login
    def handle_login(self):
        email = self.login_email_entry.get()
        password = self.login_pwd_entry.get()

            #la función login _user de auth_server nos devuelve true o false y el DNI asociado
            # ya que es importante para despues y para el database
        try:
            succes, dni_user=login_user(email,password)
            if succes:
                #tras esto se llama a la siguiente venxtana donde se realiza la votación
                self.show_voting_interface(dni_user)
        except ValueError as e:
            self.status_label.config(text =str(e),foreground='red')

        
  #  Interfaz de votación

    def show_voting_interface(self,dni):
        #plataforma de votacion
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

# Interfaz para la votación
class VotingInterface(tk.Toplevel):
    def __init__(self, master,dni,auth_server, ballot_box, bb_pub_pem):
        #tk.Toplevel crea una ventana secundaria
        super().__init__(master)
        self.title("Plataforma de votación")
        self.geometry("400x300")
        self.configure(background="#f0f0f0")

        #Datos y módulos clave
        self.dni = dni
        self.auth_server = auth_server
        self.election_id = "Ley 1"
        self.ballot_box = ballot_box
        self.bb_pub_pem = bb_pub_pem

        
        #Token de elegibilidad
        self.eligibility_token = None

        #título de la ley
        self.law_title_label= ttk.Label(self,text =f"Ley a votar:{self.election_id}",
                  font=('Arial',12,'bold'))
        self.law_title_label.pack(pady=10)
        

        #Boton para cambiar de ley
        ttk.Button(self, text = 'Cambiar ley',command=self.show_election_selector).pack(pady=5)

        #Etiqueta de estado
        self.status_label = ttk.Label(self,text="obteniendo token",foreground="blue")
        self.status_label.pack(pady=5)
        self.crypto_client = ClientCrypto(bb_pub_pem)

        #Frame para los botones de votación
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=20)

        #Botones de vot
        ttk.Button(button_frame, text='✅ Voto a favor', command= lambda: self.handle_vote("SI")).pack(side=tk.LEFT, padx= 15)
        ttk.Button(button_frame, text='❌ Voto en contra', command= lambda: self.handle_vote("NO")).pack(side=tk.LEFT, padx= 15)
        ttk.Button(button_frame, text='⚪️ Abstención', command= lambda: self.handle_vote("ABSTENCIÓN")).pack(side=tk.LEFT, padx= 15)

       

    def show_election_selector(self):
        """ Muestra una ventana para elegir una nueva ley y reiniciar la votación
        """
        laws= {"Ley 1": "Propuesta de Ley 1",
               "Ley 2":"Propuesta de Ley 2",
               "Ley 3": "Propuesta de Ley 3"
               }
        
        #Configuración de la ventana de selección
        selector_window = tk.Toplevel(self)
        selector_window.title("Seleccionar Ley")
        selector_window.transient(self)#hace que la ventana este arriba siempre

        ttk.Label(selector_window, text = "Elige la Ley para la que quieres votas").pack(padx=20,pady=10)

            #Gestor de la selección
        def select_law(law_id, law_name):
            #Cierra la ventana de selección anterior
            selector_window.destroy()
            self.election_id = law_id
            self.law_title_label.config(text= f"Ley a votar: {self.election_id}")
            self.status_label.config(text = f"Cambio a :{law_name}",foreground= "blue")

            #Limpia el token anterior y reinicia el proceso de elegibilidad
            self.eligibility_token = None
            #Botones para cada ley
        for law_name, law_id in laws.items():
            ttk.Button(selector_window,text = law_name,
                    command=lambda l_id=law_id,l_name=law_name:select_law(l_id,l_name)).pack(pady =5, padx=20)

    
    def get_eligibility_token(self):
        """ Llamada AuthServer para obtener el token """

        if self.eligibility_token:
            return True
        try:
            #comprobamos con authserver que el user no haya votado ya esa ley
            token = self.auth_server.issue_token(self.dni,self.election_id)

            self.eligibility_token = token

            #Actualizar a la ley actual
            self.law_title_label.config (text= f"Ley Actual: {self.election_id}")
            self.status_label.config(text= f"Token obtenido. DNI{self.dni [-4:]}...", foreground = "green")
            return True

        except ValueError as e:
            self.status_label.config(text = f"ERROR: {e}", foreground= "red")
            messagebox.showerror("Error de Voto", str(e))
            return False
            
        #Para cualquier otro error
        except Exception as e:
            self.status_label.config(text = f"ERROR AS : {e}", foreground= "red")
            messagebox.showerror("Error Crítico ",f"No se pudo obtener el token: {e}" )
            return False
  
        
    
    def handle_vote(self, vote_choice:str):
        """ Cifra firma y prepara el voto para llevarlo a la urna """

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
                messagebox.showinfo("Voto Exitoso", "Su voto ha sido registrado. Gracias por participar")
            else:
                #si el token es invalido
                messagebox.showerror("Voto rechazado", f"voto rechazado por la Urna Electrónica (Fallo de seguridad/integridad)")
        except Exception as e :
            messagebox.showerror("Error de Urna", f"Fallo en la Urna al procesar el voto:{e}")
            succes = False
        
        #Finalizar
        self.destroy() #Cerrar ventana de votación


    
    




if __name__ == "__main__":
    db_init()
    # Clave compartida AS/BB para HMAC de tokens (32 bytes)
    K_issue = os.urandom(32)
    AS = AuthServer(K_issue)
    BB = BallotBox(K_issue)
    app = App(AS,BB,  BB.pub_pem)
    app.mainloop()
