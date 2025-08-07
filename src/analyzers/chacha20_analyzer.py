import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich import print
import os, struct

class ChaCha20_Analyzer:

    def filtrer_dictionnaire_par_indices(self, chemin_fichier_chiffre):
        pass


    
    def generer_cle_candidates(self, chemin_fichier_chiffre):
        '''
            Cette fonction se charge de générer les clés candidates pour le déchiffremment du fichier chiffré en utilisant
            la dérivation sha256 pour renforcer les clées de chiffrement.               
                            

            Args: 
                chemin_fichier_chiffre(str) : Le chemin vers le fichier chiffré
        
            Returns:
                cles_candidates (list[bytes]) : Un tableau de clés, chaque clé étant une séquence d'octets  
        
        '''
        
        donnees_fichier_filtre = self.filtrer_dictionnaire_par_indices(chemin_fichier_chiffre)

        cle_candidates: list[bytes] = []
        for cle in donnees_fichier_filtre:
            cle_candidates.append(hashlib.sha256(cle).encode(encoding="utf-8"))

        return cle_candidates
    
    def dechiffrer(self,chemin_fichier_chiffer : str ,clef :bytes)->str:
        if len(clef) != 32 : return ValueError("Erreur : La clé a pas la taille correcte ")
        else: 
            try:
                with open(f"data/{chemin_fichier_chiffer}",'rb') as f:
                    nonce = f.read(16)
                    texte_chiffrer = f.read()

                counter=0
                algorithm_chacha20 = algorithms.ChaCha20(clef,nonce)
                cipher = Cipher(algorithm_chacha20,mode=None)
                decrypteur = cipher.decryptor()
                return decrypteur.update(texte_chiffrer)
            except Exception as e:
                print(f"Une erreur est survenu : {e}")


# print(ChaCha20_Analyzer().dechiffrer("mission2.enc",os.urandom(32)))