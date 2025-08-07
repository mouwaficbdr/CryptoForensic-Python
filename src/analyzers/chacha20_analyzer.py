# Import des modules
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich import print
import os, struct
import math

# Import de la classe CryptoAnalyzer
from ..crypto_analyzer import CryptoAnalyzer

# Définition de la classe ChaCha20_Analyzer
class ChaCha20_Analyzer(CryptoAnalyzer):
    """
    Détermine si l'algo ChaCha20 est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
    
    Cette classe a trois méthodes:
    - identifier_algo: Détermine si l'algo de chiffrement utilisé sur le fichier chiffré qui lui est passé en paramètre est l'ChaCha20.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
    _CHACHA20_LONGUEUR_CLE: la taille de la clé de chiffrement (32 octets)
    _CHACHA20_LONGUEUR_NONCE: la taille du vecteur d'initialisation (12 octets)
    _CHACHA20_LONGUEUR_TAG: la taille de l'empreinte de chiffrement (16 octets)
    _CHACHA20_LONGUEUR_BLOC: la taille du bloc de chiffrement (64 bits)
    """

    _CHACHA20_LONGUEUR_CLE = 32
    _CHACHA20_LONGUEUR_NONCE = 12 #fourni
    _CHACHA20_LONGUEUR_TAG = 16
    _CHACHA20_LONGUEUR_BLOC = 64

    def calculer_entropie(self, data: bytes) -> float:
        """
        Calcule l'entropie de Shannon d'une séquence d'octets.
        
        Args:
            data (bytes): Les données à analyser
            
        Returns:
            float: L'entropie calculée (0-8 bits par octet)
        """
        if not data:
            return 0.0
        
        # Compter les occurrences de chaque octet
        compteur = [0] * 256
        for byte in data:
            compteur[byte] += 1
        
        # Calculer l'entropie
        entropie = 0.0
        longueur = len(data)
        
        for count in compteur:
            if count > 0:
                probabilite = count / longueur
                entropie -= probabilite * math.log2(probabilite)
        
        return entropie

    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        """
        Détermine la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 en:
        - vérifiant la présence d'un nonce de 12 bytes en début de fichier
        - vérifiant l'entropie très élevée sur l'ensemble des données
        - vérifiant l'absence de padding (pas de contrainte de taille)
        - vérifiant que la taille du fichier est suffisante pour contenir un nonce
        
        Retourne une probabilité entre 0 et 1(Pour connaitre la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20).
        
        Args:
            chemin_fichier_chiffre(str): le chemin du fichier chiffré à traiter .
            
        Returns:
            float: La probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 apres le calcul.
        """
        try:
            with open(chemin_fichier_chiffre, 'rb') as f:
                donnees = f.read()
            
            if len(donnees) < self._CHACHA20_LONGUEUR_NONCE:
                return 0.0  # Fichier trop petit pour contenir un nonce
            
            # Extraire le nonce présumé (12 premiers bytes)
            nonce_presume = donnees[:self._CHACHA20_LONGUEUR_NONCE]
            donnees_chiffrees = donnees[self._CHACHA20_LONGUEUR_NONCE:]
            
            if len(donnees_chiffrees) == 0:
                return 0.0  # Pas de données chiffrées
            
            # Critère 1: Vérifier la taille minimale (nonce + au moins quelques bytes de données)
            score_taille = 1.0 if len(donnees) >= self._CHACHA20_LONGUEUR_NONCE + 16 else 0.0
            
            # Critère 2: Vérifier l'entropie des données chiffrées (doit être très élevée)
            entropie = self.calculer_entropie(donnees_chiffrees)
            # L'entropie d'un chiffrement ChaCha20 devrait être proche de 8 bits/octet
            score_entropie = min(entropie / 8.0, 1.0)
            
            # Critère 3: Vérifier l'absence de padding (pas de contrainte de taille)
            # ChaCha20 est un chiffrement de flux, donc pas de padding
            # On vérifie que la taille des données chiffrées n'est pas un multiple d'une taille de bloc commune
            taille_donnees = len(donnees_chiffrees)
            score_padding = 1.0  # Par défaut, on suppose pas de padding
            
            # Vérifier si la taille est un multiple de tailles de bloc communes (AES = 16, DES = 8)
            if taille_donnees % 16 == 0 or taille_donnees % 8 == 0:
                score_padding = 0.5  # Réduire le score si c'est un multiple de tailles de bloc communes
            
            # Critère 4: Vérifier l'entropie du nonce (doit être élevée aussi)
            entropie_nonce = self.calculer_entropie(nonce_presume)
            score_nonce = min(entropie_nonce / 8.0, 1.0)
            
            # Calcul de la probabilité finale (moyenne pondérée des scores)
            probabilite = (score_taille * 0.1 + 
                          score_entropie * 0.4 + 
                          score_padding * 0.3 + 
                          score_nonce * 0.2)
            
            return min(probabilite, 1.0)
            
        except Exception as e:
            print(f"Erreur lors de l'identification de l'algorithme: {e}")
            return 0.0

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
            cle_candidates.append(hashlib.sha256(cle).digest())

        return cle_candidates
    
    def dechiffrer(self, chemin_fichier_chiffre: str, clef: bytes) -> str:
        if len(clef) != 32: 
            raise ValueError("Erreur : La clé n'a pas la taille correcte")
        else: 
            try:
                with open(f"data/{chemin_fichier_chiffre}", 'rb') as f:
                    nonce = f.read(self._CHACHA20_LONGUEUR_NONCE)
                    texte_chiffre = f.read()

                algorithm_chacha20 = algorithms.ChaCha20(clef, nonce)
                cipher = Cipher(algorithm_chacha20, mode=None)
                decrypteur = cipher.decryptor()
                resultat = decrypteur.update(texte_chiffre)
                
                # Essayer de décoder en UTF-8 avec gestion d'erreurs
                try:
                    return resultat.decode('utf-8')
                except UnicodeDecodeError:
                    return resultat.decode('utf-8', errors='ignore')

            except Exception as e:
                print(f"Une erreur est survenue : {e}")
                return None


# print(ChaCha20_Analyzer().dechiffrer("mission2.enc",os.urandom(32)))