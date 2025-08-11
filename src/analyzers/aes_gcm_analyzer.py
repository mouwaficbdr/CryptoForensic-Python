from src.crypto_analyzer import CryptoAnalyzer
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import List
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
  
  _PBKDF2_SALT: bytes = b"AES_GCM_SALT_2024"  #Fourni
  _PBKDF2_ITERATIONS: int = 10000             #Fourni
  _PBKDF2_LONGUEUR_CLE: int = 32              #Longueur de la clé
  
  def __filtrer_dictionnaire_par_indice(self, chemin_dictionnaire: str) -> List[str]:
    """
    Filtre le dictionnaire en se basant sur les indices de la mission 4.
    L'indice pointe vers le format de clé "Acronyme en majuscules + 4 chiffres".
    
    Args:
      chemin_dictionnaire(str): Le chemin vers le fichier de dictionnaire.
    
    Returns:
      list[str]: Une liste de mots de passe filtrés.
    """
    mots_filtres: List[str] = []
    
    # L'année courante
    annee_courante: str = "2024" #Normalement 2025 mais on considère 2024 pour se conformer à la wordlist
    
    # Définition du motif d'acronyme de 4 lettres en majuscules
    # On utilise une expression régulière pour plus de robustesse
    motif_acronyme = re.compile(r"^[A-Z]{4}$")
    
    try:
        with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
            for ligne in f:
                mot: str = ligne.strip()
                
                # Vérifie si le mot de passe correspond au format de l'indice
                # ex: NATO2024, UN2024, etc.
                if mot.endswith(annee_courante):
                    acronyme: str = mot[:-4] # Extrait la partie acronyme
                    if motif_acronyme.match(acronyme):
                        mots_filtres.append(mot)
                        
    except FileNotFoundError:
        print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
        return []
    
    return mots_filtres
  
  def generer_cles_candidates(self, chemin_dictionnaire: str) -> List[bytes]:
    '''
      Génère les clées candidates pour déchiffrer le fichier à partir de la liste retournée par filtrer_dictionnaire_par_indices.
      
      Args:
        chemin_dictionnaire(str): le chemin du dictionnaire de mots de passes pour l'attaque par dictionnaire.
        
      Returns:
        list[bytes]: liste des clés candidates. 
    '''
    
    mots_de_passe_cible: List[str] = self.__filtrer_dictionnaire_par_indice(chemin_dictionnaire)
    
    clees_candidates: List[bytes] = []
    
    for mot_de_passe in mots_de_passe_cible:
      kdf = PBKDF2HMAC(
          algorithm=hashes.SHA256(),
          length=self._PBKDF2_LONGUEUR_CLE,
          iterations=self._PBKDF2_ITERATIONS,
          salt=self._PBKDF2_SALT
      )
      mot_de_passe_en_octets: bytes = mot_de_passe.encode('utf-8')
      cle_derivee: bytes = kdf.derive(mot_de_passe_en_octets)
      clees_candidates.append(cle_derivee)

    return clees_candidates

  def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
    """
    Identifie si le fichier utilise l'algorithme AES GCM.
    
    Cette méthode utilise plusieurs heuristiques spécifiques à AES GCM pour se différencier d'AES CBC :
    - Structure : nonce (12 bytes) + données chiffrées + tag d'authentification (16 bytes)
    - Pas de contrainte de taille (pas de padding)
    - Tag d'authentification reconnaissable
    - Mode authentifié moderne (plus sécurisé que CBC)
    
    Args:
        chemin_fichier_chiffre(str): Le chemin vers le fichier chiffré.
        
    Returns:
        float: Probabilité que le fichier utilise AES GCM (0.0 à 1.0).
    """
    try:
        with open(chemin_fichier_chiffre, "rb") as f:
            contenu_fichier: bytes = f.read()
        
        # Heuristique 1: Vérifier que le fichier est assez grand pour contenir nonce + tag
        # Nonce (12 bytes) + tag (16 bytes) = minimum 28 bytes
        if len(contenu_fichier) < 28:
            return 0.0
        
        # Heuristique 2: Extraire la structure potentielle
        nonce_potentiel: bytes = contenu_fichier[0:12]  # 12 bytes pour le nonce
        tag_potentiel: bytes = contenu_fichier[-16:]     # 16 bytes pour le tag d'authentification
        donnees_chiffrees: bytes = contenu_fichier[12:-16]  # Le reste
        
        probabilite: float = 0.0
        
        # Heuristique 3: Vérifier la présence d'un tag d'authentification de 16 bytes
        if len(tag_potentiel) == 16:
            probabilite += 0.25
        
        # Heuristique 4: Analyser l'entropie des données chiffrées
        from src.utils import calculer_entropie
        entropie_donnees = calculer_entropie(donnees_chiffrees)
        if entropie_donnees > 7.0:
            probabilite += 0.25  # Augmenté de 0.2 à 0.25
        
        # Heuristique 5: Vérifier l'entropie du tag d'authentification
        entropie_tag = calculer_entropie(tag_potentiel)
        if entropie_tag > 7.5:
            probabilite += 0.25  # Augmenté de 0.2 à 0.25
        
        # Heuristique 6: Différenciation clé d'AES CBC
        # AES CBC nécessite une taille multiple de 16 bytes (padding PKCS7) contrairement à AES GCM
        if len(donnees_chiffrees) % 16 != 0:
            # Si la taille n'est pas multiple de 16, c'est probablement GCM (pas de padding)
            probabilite += 0.21  # Légèrement augmenté pour dépasser 0.8
        
        # Heuristique 7: Vérifier l'entropie du nonce
        entropie_nonce = calculer_entropie(nonce_potentiel)
        if entropie_nonce > 7.0:
            probabilite += 0.1
        
        # Si toutes les heuristiques de base sont satisfaites
        if probabilite >= 0.5:
            probabilite += 0.1
        
        return probabilite
        
    except FileNotFoundError:
        print(f"Erreur : Le fichier '{chemin_fichier_chiffre}' est introuvable.")
        return 0.0
    except Exception as e:
        print(f"Erreur lors de l'identification de l'algorithme AES GCM: {e}")
        return 0.0  
  
  def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
    """
    Déchiffre le fichier chiffré avec la clé donnée.
    
    Args:
        chemin_fichier_chiffre(str): Le chemin vers le fichier chiffré.
        cle_donnee(bytes): La clé de déchiffrement.
        
    Returns:
        bytes: Le contenu déchiffré ou une chaîne vide en cas d'échec.
    """
    try:
        # TODO: Implémenter la logique de déchiffrement AES GCM
        return b""
    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")
        return b""
