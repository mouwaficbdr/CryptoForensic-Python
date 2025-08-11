import base64
import binascii
import hashlib
import time
from cryptography.fernet import Fernet
from typing import List

from src.crypto_analyzer import CryptoAnalyzer

class FernetAnalyzer(CryptoAnalyzer):
    """
    Détermine si l'algo Fernet est utilisé, génère des clés et tente de déchiffrer
    un fichier chiffré en utilisant les clés générées.
    
    Cette classe a trois méthodes principales:
    - identifier_algo: Détermine si l'algo de chiffrement utilisé sur le fichier chiffré 
      qui lui est passé en paramètre est Fernet.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement 
      du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
        _FERNET_VERSION: le byte de version du format Fernet
        _FERNET_MIN_TAILLE: taille minimale d'un token Fernet valide
    """
    
    _FERNET_VERSION: bytes = b'\x80'  # Le byte de version du format Fernet
    _FERNET_MIN_TAILLE: int = 1 + 8 + 16 + 32  # version + timestamp + iv + hmac
    
    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        """
        Détermine la probabilité que l'algo de chiffrement soit Fernet en vérifiant
        le format Base64 URL-safe, le byte de version et la structure du jeton.
        
        Heuristiques utilisées:
        - Format Base64 URL-safe: 30% du score
        - Taille minimale: 20% du score
        - Version correcte: 30% du score
        - Horodatage valide: 20% du score
        
        Args:
            chemin_fichier_chiffre (str): Le chemin du fichier chiffré à traiter.
            
        Returns:
            float: Score de probabilité entre 0.0 et 1.0.
        """
        score: float = 0.0
        
        try:
            with open(chemin_fichier_chiffre, "rb") as f:
                contenu_fichier = f.read()
            
            # 1. Vérification du format Base64 URL-safe.
            contenu_decode_bytes = base64.urlsafe_b64decode(contenu_fichier)
            score += 0.3
                
            # 2. Vérification de la taille minimale.
            if len(contenu_decode_bytes) >= self._FERNET_MIN_TAILLE:
                score += 0.2
            else:
                return 0.0
            
            # 3. Vérification du premier octet (version 0x80).
            premier_octet = contenu_decode_bytes[:1]
            if premier_octet == self._FERNET_VERSION:
                score += 0.3
            else:
                return 0.0
            
            # 4. Vérification de l'horodatage.
            horodatage_bytes = contenu_decode_bytes[1:9]
            horodatage_entier = int.from_bytes(horodatage_bytes, 'big')
            
            # Vérifie que le timestamp est dans une marge réaliste (après 2020 et avant l'heure actuelle).
            # 1577836800 correspond au 1er janvier 2020.
            if horodatage_entier > 1577836800 and horodatage_entier <= time.time(): 
                score += 0.2
            else:
                return 0.0
                
        except FileNotFoundError:
            return 0.0
        except (binascii.Error, ValueError):
            return 0.0
        
        return score

    def __filtrer_dictionnaire_par_indice(self, chemin_dictionnaire: str) -> List[str]:
        """
        Filtre le dictionnaire en se basant sur les indices de la mission 5.
        L'indice pointe vers le format "Phrase complète en français minuscules avec espaces".
        
        Cette méthode cherche des phrases en minuscules de plus de 5 caractères avec au moins un espace.
        
        Args:
            chemin_dictionnaire (str): Le chemin vers le fichier de dictionnaire.
        
        Returns:
            List[str]: Une liste de mots de passe (phrases) filtrés.
        """
        mots_filtres: List[str] = []
        
        try:
            with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
                for ligne in f:
                    mot = ligne.strip()
                    
                    # Vérifie si le mot est en minuscules, contient au moins un espace et a une longueur raisonnable.
                    if mot.islower() and ' ' in mot and len(mot) > 5:
                        mots_filtres.append(mot)
                        
        except FileNotFoundError:
            print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
            return []
        
        return mots_filtres

    def generer_cles_candidates(self, chemin_dictionnaire: str) -> List[bytes]:
        """
        Génère une liste de clés candidates Fernet (32 octets) en dérivant
        une clé SHA256 à partir des mots de passe filtrés et en l'encodant en Base64.

        Args:
            chemin_dictionnaire (str): Le chemin vers le fichier de dictionnaire.
        
        Returns:
            List[bytes]: Une liste des clés candidates.
        """
        mots_de_passe_cible = self.__filtrer_dictionnaire_par_indice(chemin_dictionnaire)
        cles_candidates: List[bytes] = []
        
        for mot_de_passe in mots_de_passe_cible:
            # Dérivation de la clé avec SHA256
            cle_derivee = hashlib.sha256(mot_de_passe.encode('utf-8')).digest()
            # Encodage en Base64 pour Fernet
            cle_base64 = base64.urlsafe_b64encode(cle_derivee)
            cles_candidates.append(cle_base64)

        return cles_candidates

    def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
        """
        Tente de déchiffrer un fichier chiffré à partir d'une clé prise en paramètre.
        Elle utilise la bibliothèque Fernet pour tenter le déchiffrement.
        
        Args:
            chemin_fichier_chiffre (str): chemin du fichier chiffré à déchiffrer
            cle_donnee (bytes): clé candidate pour le déchiffrement
        
        Returns:
            bytes: données déchiffrées ou chaîne vide en cas d'échec
        """
        try:
            # Validation de la taille de clé (Fernet nécessite 44 bytes en Base64)
            if len(cle_donnee) != 44:
                raise ValueError("Erreur : La clé Fernet doit faire 44 bytes en Base64")
            
            try:
                # Création de l'objet Fernet pour le déchiffrage
                fernet = Fernet(cle_donnee)
                
                # Lecture du fichier chiffré
                with open(chemin_fichier_chiffre, "rb") as f:
                    donnees_chiffrees = f.read()
                
                # Tentative de déchiffrement
                donnees_originales = fernet.decrypt(donnees_chiffrees)
                
                return donnees_originales
                
            except Exception as e:
                # Erreur de déchiffrement (clé incorrecte, format invalide)
                return b""
                
        except FileNotFoundError:
            raise
        except ValueError as e:
            # Erreur de validation de la clé
            if "doit faire 44 bytes" in str(e):
                raise
            return b""