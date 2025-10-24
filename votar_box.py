


class BallotBox:
    """ 
    Clase que simula la urna electronica "BB" servidor de recepción de votos.
    Este usara k_issue para verificar la autenticidad de los tokens de elegibilidad.
    """

    def __init__(self,issue_key:bytes):
        #misma clave compartida de AuthServer.
        self.K_issue = issue_key
        print("BallotBox inicializado")


    #resto de funciones..
    #def receive_vote(self,token,ecrypted_vote,signature):
    #etc etc

