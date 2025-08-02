from ..crypto_analyzer import CryptoAnalyzer
from ..utils import calculer_entropie
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class Aes_Cbc_Analyzer(CryptoAnalyzer): 
  
  _PBKDF2_SALT = b"sel_secret"
  _PBKDF2_ITERATIONS = 10000
  _PBKDF2_LONGUEUR_CLE = 32
  
  def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
    '''
      Détermine la probabilité que l'algo de chiffrement utilisé soit l'aes cbc.
      
      Args:
        chemin_fichier_chiffre(str): Le chemin du fichier chiffré à traiter (mission1.enc).
      
      Returns:
        float: probabilité calculée.
    '''
    
    try:
      with open(chemin_fichier_chiffre, "rb") as f:
        contenu_fichier = f.read()
      
        if len(contenu_fichier) < 16: #Heuristique IV probable en début de fichier (Vérifie si le fichier est assez grand pour contenir déjà l'IV)
          return 0.0
  
        initialization_vector = contenu_fichier[0:16]  # type: ignore
        donnees_chiffres = contenu_fichier[16:]
        
        if len(donnees_chiffres) % 16 == 0: #Heuristique taille multipe de 16 bytes (Vérifie si les donnéese chiffrés sont en bloc de 16 octets, caractéristique de l'aes cbc)
          probabilite = 0.6
        else:
          return 0.0
        
        entropie = calculer_entropie(donnees_chiffres)
        
        if entropie > 7.5: #Heuristique entropie élevée (L'entropie doit être supérieur à 7.5 pour confirmer le chiffrement robuste caractéristique des algos de chiffrement)
          probabilite += 0.4
        else:
          return 0.0
        
    except FileNotFoundError:
      print("Le fichier spécifié n'existe pas.")
      return 0.0
      
    return probabilite
  
  def generer_cles_candidates(self, chemin_dictionnaire: str) -> list[bytes]:
    '''
      Génère les clées candidates pour déchiffrer le fichier à partir d'un dictionnaire en utilisant PBKDF2 pour dériver la clé par mot du dictionnaire.
      
      Args:
        chemin_dictionnaire(str): le chemin du dictionnaire de mots de passes pour l'attaque par dictionnaire.
        
      Returns:
        list[bytes]: liste des clés candidates.
    '''
    
    clees_candidates: list[bytes] = []
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=self._PBKDF2_LONGUEUR_CLE,
      iterations=self._PBKDF2_ITERATIONS,
      salt=self._PBKDF2_SALT
    )
    try:
      with open(chemin_dictionnaire, "r") as f: 
        for ligne in f:
          mot_de_passe_propre: str = ligne.strip()
          mot_de_passe_en_octets: bytes = mot_de_passe_propre.encode('utf-8')
          cle_derivee: bytes = kdf.derive(mot_de_passe_en_octets)
          clees_candidates.append(cle_derivee)
    except FileNotFoundError:
      print("Le fichier spécifié n'existe pas.")
      return []
    
    return clees_candidates
  
  def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
    try:
      with open(chemin_fichier_chiffre, "rb") as f:
        initialization_vector = f.read(16)
        donnees_chiffrees = f.read()
        
        try:
          #Création de l'objet Cipher pour le déchiffrage
          algorithm_aes = algorithms.AES256(cle_donnee)
          mode_cbc = modes.CBC(initialization_vector)
          cipher = Cipher(algorithm_aes, mode_cbc)
          
          #Inistanciation du dechiffreur à partir du cipher
          decrypteur = cipher.decryptor()
          
          #Instanciation du supresseur de padding
          supresseur_padding = PKCS7(algorithm_aes.block_size).unpadder()
          
          donnees_chiffrees_avec_padding = decrypteur.update(donnees_chiffrees) + decrypteur.finalize()
          donnees_originales = supresseur_padding.update(donnees_chiffrees_avec_padding) + supresseur_padding.finalize()
          
          return donnees_originales
        
        except ValueError:
          print("La clé n'est pas la bonne")
          return b""
          
    except FileNotFoundError:
      print("Le fichier spécifié n'existe pas")
      return b""