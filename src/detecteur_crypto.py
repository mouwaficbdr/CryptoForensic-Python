import AesCbcAnalyzer
from crypto_analyzer import identifier_algo

"""
        Classe principale qui centralise tout:
            -Lance l’analyse des fichiers et identifie l'algorithme probable,
            -Lance les attaquespar dictionnaire,
            -Lance et coordonnes le processus de dechiffrement 
"""
class DetecteurCryptoOrchestrateur:
    """
        Initialisation de l'analyseur AES-CBC     
    """
    def __init__(self):
        self.aes_cbc_analyzer = AesCbcAnalyzer()
        

