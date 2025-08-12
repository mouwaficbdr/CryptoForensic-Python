import sys
import time
from src.detecteur_crypto import DetecteurCryptoOrchestrateur, ResultatAnalyse
from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.interface_console import consoleInterface
import os
from rich.progress import track
# print(DetecteurCryptoOrchestrateur().analyser_fichier_specifique('data/mission1.enc'))

# try:
#     resultat_dechiffrement: bytes = Blowfish_Analyzer().dechiffrer("data/mission3.enc", Blowfish_Analyzer().generer_cles_candidates('keys/wordlist.txt')[2])
#     print(f"Résultat du déchiffrement : {resultat_dechiffrement.decode('utf-8')}")
# except ValueError as ve:
#     print(ve)
# except FileNotFoundError:
#     print("Erreur: Le fichier 'mission3.enc' est introuvable.")

consoleInterface()
# print(DetecteurCryptoOrchestrateur().mission_complete_automatique('data/', 'keys/wordlist.txt'))

