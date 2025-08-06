import hashlib

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