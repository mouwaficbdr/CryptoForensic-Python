from src.crypto_analyzer import CryptoAnalyzer
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from src.utils import calculer_entropie
import re

class Aes_Gcm_Analyzer(CryptoAnalyzer):
  '''Détermine si l'algo aes_gcm est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
  
    Cette classe a trois méthodes principales:
    - identifier_algo: Détermine si l'algo de chiffrement utilsé sur le fichier chiffré qui lui est passé en paramètre est l'aes_gcm.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
    _PBKDF2_SALT: le salt utilisé pour le chiffrement
    _PBKDF2_ITERATIONS: le nombre d'itérations faites au chiffrement
    _PBKDF2_LONGUEUR_CLE: la longueur en octets de la clé à utiliser

  '''
  
  _PBKDF2_SALT = b"AES_GCM_SALT_2024" #Fourni
  _PBKDF2_ITERATIONS = 10000  #Fourni
  _PBKDF2_LONGUEUR_CLE = 32 #Longueur de la clé
  
  def __filtrer_dictionnaire_par_indice(self, chemin_dictionnaire: str) -> list[str]:
    """
    Filtre le dictionnaire en se basant sur les indices de la mission 4.
    L'indice pointe vers le format de clé "Acronyme en majuscules + 4 chiffres".
    
    Args:
      chemin_dictionnaire(str): Le chemin vers le fichier de dictionnaire.
    
    Returns:
      list[str]: Une liste de mots de passe filtrés.
    """
    mots_filtres: list[str] = []
    
    # L'année courante
    annee_courante = "2024" #Normalement 2025 mais on considère 2024 pour se conformer à la wordlist
    
    # Définition du motif d'acronyme de 4 lettres en majuscules
    # On utilise une expression régulière pour plus de robustesse
    motif_acronyme = re.compile(r"^[A-Z]{4}$")
    
    try:
        with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
            for ligne in f:
                mot = ligne.strip()
                
                # Vérifie si le mot de passe correspond au format de l'indice
                # ex: NATO2024, UN2024, etc.
                if mot.endswith(annee_courante):
                    acronyme = mot[:-4] # Extrait la partie acronyme
                    if motif_acronyme.match(acronyme):
                        mots_filtres.append(mot)
                        
    except FileNotFoundError:
        print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
        return []
    
    return mots_filtres
  
  def generer_cles_candidates(self, chemin_dictionnaire: str) -> list[bytes]:
    '''
      Génère les clées candidates pour déchiffrer le fichier à partir de la liste retournée par filtrer_dictionnaire_par_indices.
      
      Args:
        chemin_dictionnaire(str): le chemin du dictionnaire de mots de passes pour l'attaque par dictionnaire.
        
      Returns:
        list[bytes]: liste des clés candidates. 
    '''
    
    mots_de_passe_cible = self.__filtrer_dictionnaire_par_indice(chemin_dictionnaire)
    
    clees_candidates: list[bytes] = []
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=self._PBKDF2_LONGUEUR_CLE,
      iterations=self._PBKDF2_ITERATIONS,
      salt=self._PBKDF2_SALT
    )
    for mot_de_passe in mots_de_passe_cible:
      mot_de_passe_en_octets: bytes = mot_de_passe.encode('utf-8')
      cle_derivee: bytes = kdf.derive(mot_de_passe_en_octets)
      clees_candidates.append(cle_derivee)

    return clees_candidates

  def identifier_algo(self, chemin_fichier_chiffre):
     try :
      with open(chemin_fichier_chiffre,'rb') as f:
          if len(f.read()) < 28 : # Prise en compte de l'entropie (12 bytes) et du tag (16 bytes) comme taille minimales pour un cryptage AES-GCM
            proba = 0.00
          if calculer_entropie(f.read()) > 8 :
            proba = 0.60
     except FileNotFoundError  :
        return 0.0
     
     return proba
   
  def dechiffrer(self, chemin_fichier_chiffre, cle_donnee):
      return super().dechiffrer(chemin_fichier_chiffre, cle_donnee)
  
Aes_Gcm_Analyzer().identifier_algo("data/mission2.enc")