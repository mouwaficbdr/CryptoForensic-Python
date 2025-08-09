import base64
import binascii
import hashlib
import time
from cryptography.fernet import Fernet
from typing import List

from ..crypto_analyzer import CryptoAnalyzer

class FernetAnalyzer(CryptoAnalyzer):
  """
  Détermine si l'algo Fernet est utilisé, génère des clés et tente de déchiffrer
  un fichier chiffré en utilisant les clés générées.
  """
  
  _FERNET_VERSION = b'\x80' # Le byte de version du format Fernet
  _FERNET_MIN_TAILLE = 1 + 8 + 16 + 32 # version + timestamp + iv + hmac
  
  def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
    """
    Détermine la probabilité que l'algo de chiffrement soit Fernet en vérifiant
    le format Base64 URL-safe, le byte de version et la structure du jeton.
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

  def _filtrer_dictionnaire_par_indices(self, chemin_dictionnaire: str) -> List[str]:
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
      List[bytes]: Une liste des clés candidates sous forme d'octets.
    """
    cles_candidates: List[bytes] = []
    
    phrases_candidates = self._filtrer_dictionnaire_par_indices(chemin_dictionnaire)
    
    #On dérive la clé Fernet pour chaque phrase candidate.
    for phrase in phrases_candidates:
      # Fernet attend une clé de 32 octets
      cle_sha256 = hashlib.sha256(phrase.encode("utf-8")).digest()
      
      
      # Pour cette mission, la clé est juste le hachage.
      cles_candidates.append(cle_sha256)
      
    return cles_candidates

  # Version corrigée de la méthode `dechiffrer`
  def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
      """
      Tente de déchiffrer un fichier chiffré Fernet.
      
      Args:
        chemin_fichier_chiffre (str): Le chemin du fichier chiffré.
        cle_donnee (bytes): Une clé candidate de 32 octets.
        
      Returns:
        bytes: Les données déchiffrées en cas de succès.
      
      Raises:
        FileNotFoundError: Si le fichier est introuvable.
        ValueError: Si le déchiffrement échoue.
      """
      try:
        with open(chemin_fichier_chiffre, "rb") as f:
          jeton_fernet_bytes = f.read()

        cle_fernet = Fernet(base64.urlsafe_b64encode(cle_donnee))
        
        donnees_dechiffrees = cle_fernet.decrypt(jeton_fernet_bytes)
        return donnees_dechiffrees
        
      except FileNotFoundError:
        raise
      except Exception:
        # Lève une erreur générique pour les échecs de déchiffrement (clé incorrecte, etc.)
        raise ValueError("Échec du déchiffrement avec cette clé.")