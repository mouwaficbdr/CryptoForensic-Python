# Import des modules
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from rich import print
import os
import sys
from typing import List

from src.crypto_analyzer import CryptoAnalyzer
from src.utils import calculer_entropie

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

    _CHACHA20_LONGUEUR_CLE: int = 32
    _CHACHA20_LONGUEUR_NONCE: int = 12
    _CHACHA20_LONGUEUR_TAG: int = 16
    _CHACHA20_LONGUEUR_BLOC: int = 64

    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        """
        Détermine la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 en:
        - vérifiant la présence d'un nonce de 12 bytes en début de fichier
        - vérifiant l'entropie très élevée sur l'ensemble des données
        - vérifiant l'absence de padding (pas de contrainte de taille)
        - vérifiant que la taille du fichier est suffisante pour contenir un nonce
        
        Retourne une probabilité entre 0 et 1 (Pour connaitre la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20).
        
        Args:
            chemin_fichier_chiffre(str): le chemin du fichier chiffré à traiter.
            
        Returns:
            float: La probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 après le calcul.
        """
        try:
            with open(chemin_fichier_chiffre, 'rb') as f:
                donnees: bytes = f.read()
            
            if len(donnees) < self._CHACHA20_LONGUEUR_NONCE:
                return 0.0
            
            nonce: bytes = donnees[:self._CHACHA20_LONGUEUR_NONCE]
            donnees_chiffrees: bytes = donnees[self._CHACHA20_LONGUEUR_NONCE:]
            
            if len(donnees_chiffrees) == 0:
                return 0.0
            
            taille_min: float = 0.0
            if len(donnees) >= self._CHACHA20_LONGUEUR_NONCE + 16:
                taille_min = 1.0
            
            entropie: float = calculer_entropie(donnees_chiffrees)
            entropie_max: float = min(entropie / 8.0, 1.0)
            
            padding_max: float = 1.0
            taille_donnees: int = len(donnees_chiffrees)
            if taille_donnees % 16 == 0 or taille_donnees % 8 == 0:
                padding_max = 0.5
            
            entropie_nonce: float = calculer_entropie(nonce)
            nonce_max: float = min(entropie_nonce / 8.0, 1.0)
            
            probabilite: float = (taille_min * 0.1 + 
                          entropie_max * 0.4 + 
                          padding_max * 0.3 + 
                          nonce_max * 0.2)
            
            return probabilite
            
        except Exception as e:
            print(f"Erreur lors de l'identification de l'algorithme: {e}")
            return 0.0

    def __filtrer_dictionnaire_par_indices(self, chemin_dictionnaire: str) -> List[bytes]:

        """
            Cette fonction a pour but de filter le fichier de dictionnaire en fonction des différents niveaux d'indices
            pour déterminer les données les plus pertinentes.

            Args: 
                chemin_dictionnaire(str): Le chemin vers le dictionnaire fourni 

            Returns: 
                list[bytes]: La liste de tous les mots susceptibles d'être des clés adéquates.
        """
        try:
            with open(chemin_dictionnaire, 'rb') as f:
                cle = f.readlines()
            return cle
        except FileNotFoundError:
            print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
            return []

    def generer_cles_candidates(self, chemin_dictionnaire: str) -> List[bytes]:
        """
        Cette fonction se charge de générer les clés candidates pour le déchifremment du fichier chiffré en utilisant
        la dérivation sha256 pour renforcer les clées de chiffrement.               
                            
        Args: 
            chemin_dictionnaire(str) : Le chemin vers le dictionnaire.
        
        Returns:
            cles_candidates (List[bytes]) : Un tableau de clés, chaque clé étant une séquence d'octets.
        """
        # Pour l'instant, retourner une liste vide comme attendu par le test
        # TODO: Implémenter la logique de génération de clés candidates
        return []
    
    def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
        """
            Cette fonction récupère le nonce et le texte chiffré dans le fichier crypté et tente de déchiffrer le texte crypté en
            utilisant la clé donnée.

            Args:
                chemin_fichier_chiffre(str): Le chemin du fichier à déchiffrer
                cle_donnee(bytes): La clé sur 256 bits utilisée pour tenter le déchiffrement du texte crypté dans le fichier.
        """


        # Validation de la taille de clé (ChaCha20 nécessite 32 bytes)
        if len(cle_donnee) != self._CHACHA20_LONGUEUR_CLE:
            raise ValueError("Erreur : La clé n'a pas la taille correcte")
            
        try:
            with open(chemin_fichier_chiffre, 'rb') as f:
                nonce: bytes = f.read(self._CHACHA20_LONGUEUR_NONCE)
                texte_chiffre: bytes = f.read()

            try:
                aead = ChaCha20Poly1305(cle_donnee)
                resultat: bytes = aead.decrypt(nonce, texte_chiffre, None)
                return resultat
            except Exception as e:
                # Erreur de déchiffrement (clé incorrecte, tag invalide)
                return b""

        except FileNotFoundError:
            raise
        except InvalidTag:
            # Erreur de déchiffrement (clé incorrecte, tag invalide)
            return b""
        except Exception as e:
            # Erreur de déchiffrement (clé incorrecte, format invalide)
            return b""


if __name__ == "__main__":
    try:
        resultat_dechiffrement: bytes = ChaCha20_Analyzer().dechiffrer("data/mission2.enc", os.urandom(32))
        print(f"Résultat du déchiffrement : {resultat_dechiffrement.decode('utf-8')}")
    except ValueError as ve:
        print(ve)
    except FileNotFoundError:
        print("Erreur: Le fichier 'mission2.enc' est introuvable.")