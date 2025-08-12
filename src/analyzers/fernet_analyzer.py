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
        Estime la probabilité que le fichier soit un jeton Fernet valide.
        
        Étapes vérifiées (pondérations indiquées):
        - Encodage Base64 URL-safe (0.30): le contenu doit se décoder sans erreur.
        - Taille minimale (0.20): une trame Fernet plausible doit dépasser un seuil.
        - Byte de version (0x80) (0.30): premier octet attendu.
        - Horodatage réaliste (0.20): timestamp > 2020 et ≤ maintenant.
        
        Args:
            chemin_fichier_chiffre (str): Le chemin du fichier chifré à traiter.
            
        Returns:
            float: Score de probabilité entre 0.0 et 1.0.
        """
        score: float = 0.0
        
        try:
            with open(chemin_fichier_chiffre, "rb") as f:
                contenu_fichier = f.read()
            
            # 1) Le contenu doit être décodable en Base64 URL-safe (sinon ce n'est pas Fernet).
            contenu_decode_bytes = base64.urlsafe_b64decode(contenu_fichier)
            score += 0.3
                
            # 2) Taille minimale d'un token Fernet plausible.
            if len(contenu_decode_bytes) >= self._FERNET_MIN_TAILLE:
                score += 0.2
            else:
                return 0.0
            
            # 3) Premier octet = byte de version (0x80) attendu.
            premier_octet = contenu_decode_bytes[:1]
            if premier_octet == self._FERNET_VERSION:
                score += 0.3
            else:
                return 0.0
            
            # 4) Horodatage: doit être dans une plage réaliste.
            horodatage_bytes = contenu_decode_bytes[1:9]
            horodatage_entier = int.from_bytes(horodatage_bytes, 'big')
            
            # Vérifie que le timestamp est réaliste (après 2020 et avant l'heure actuelle).
            # 1577836800 = 1er janvier 2020.
            if horodatage_entier > 1577836800 and horodatage_entier <= time.time(): 
                score += 0.2
            else:
                return 0.0
                
        except FileNotFoundError:
            return 0.0
        except (binascii.Error, ValueError):
            return 0.0
        
        # Normalisation: on borne toujours le score dans [0, 1]
        if score < 0.0:
            score = 0.0
        if score > 1.0:
            score = 1.0
        return score

    def __filtrer_dictionnaire_par_indices(self, chemin_dictionnaire: str) -> List[str]:
        """
        Filtre le dictionnaire en se basant sur les indices de la mission 5.
        L'indice pointe vers le format "Phrase complète en français minuscules avec espaces".
        
        Cette méthode cherche des phrases en minuscules de plus de 5 caractères avec au moins un espace.
        
        Returns:
            List[str]: Une liste de mots de passe (phrases) filtrés.
        """
        mots_filtres: List[str] = []
        
        try:
            with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
                for ligne in f:
                    mot = ligne.strip()
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
        mots_de_passe_cible = self.__filtrer_dictionnaire_par_indices(chemin_dictionnaire)
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