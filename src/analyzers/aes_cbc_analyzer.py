from src.crypto_analyzer import CryptoAnalyzer
from src.utils import calculer_entropie
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class Aes_Cbc_Analyzer(CryptoAnalyzer): 
  '''Détermine si l'algo aes_cbc est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
  
    Cette classe a trois méthodes:
    - identifier_algo: Détermine si l'algo de chiffrement utilsé sur le fichier chiffré qui lui est passé en paramètre est l'aes_cbc.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
    _PBKDF2_SALT: le salt utilisé pour le chiffrement
    _PBKDF2_ITERATIONS: le nombre d'itérations faites au chiffrement
    _PBKDF2_LONGUEUR_CLE: la longueur en octets de la clé à utiliser

  '''
  
  _PBKDF2_SALT = b"AES_CBC_SALT_2024" #Fourni
  _PBKDF2_ITERATIONS = 10000  #Fourni
  _PBKDF2_LONGUEUR_CLE = 32 #Longueur de la clé
  
  def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
    '''
      Détermine la probabilité que l'algo de chiffrement utilisé soit l'aes cbc en:
      
      - recherchant l'IV en tête
      - vérifiant si le reste du fichier en dehors de l'IV a une taille multiple de 16 octets
      - déterminant si l'entropie est assez élevée dans le fichier chiffré (>7.5)
      
      Args:
        chemin_fichier_chiffre(str): Le chemin du fichier chiffré à traiter (mission1.enc).
      
      Returns:
        float: probabilité calculée.
    '''
    
    try:
      with open(chemin_fichier_chiffre, "rb") as f:
        contenu_fichier = f.read()

        if len(contenu_fichier) < 16:
          return 0.0

        iv = contenu_fichier[:16]
        corps = contenu_fichier[16:]

        score: float = 0.0

        # CBC: taille des données chiffrées multiple de 16
        if len(corps) % 16 == 0 and len(corps) > 0:
          score += 0.55
        else:
          score -= 0.25

        # Entropie globale des données
        ent = calculer_entropie(corps)
        if ent > 7.3:
          score += 0.35

        # Négatifs structure GCM: nonce 12B au début + tag 16B à la fin et corps non-multiple de 16
        if len(contenu_fichier) >= 28:
          from src.utils import calculer_entropie as entf
          nonce12 = contenu_fichier[:12]
          tag16 = contenu_fichier[-16:]
          corps_gcm = contenu_fichier[12:-16]
          if len(corps_gcm) > 0 and (
            entf(nonce12) > 7.0 and entf(tag16) > 7.0 and len(corps_gcm) % 16 != 0
          ):
            score -= 0.60

        # Clamp [0,1]
        if score < 0.0:
          score = 0.0
        if score > 1.0:
          score = 1.0
        return score

    except FileNotFoundError:
      return 0.0
  
  def __filtrer_dictionnaire_par_indices(self, chemin_dictionnaire: str) -> list[str]:
    '''
      Filtre le dictionnaire sur la base des indices fournis pour sélectionner uniquement les mots de passe pertinents.
      
      Args:
        chemin_dictonnaire(str): chemin du dictionnaire
      
      Returns:
        list[str]: liste des mots retenus
    '''
    
    mots_de_passe_cible: list[str] = []
    annees_olympiques: list[str] = ["1900", "1924", "2024"] #Annees où Paris a acceuili les JO
    
    try:
      with open(chemin_dictionnaire, "r") as f:
        for ligne in f:
          mot_propre:str = ligne.strip()
          if mot_propre.startswith("paris") and mot_propre.endswith(tuple(annees_olympiques)): #"paris" car Paris = Ville Lumière = Capitale francaise comme l'indiquent les indices
            mots_de_passe_cible.append(mot_propre)
      return mots_de_passe_cible        
    except FileNotFoundError:
      return []
    
  
  def generer_cles_candidates(self, chemin_dictionnaire: str) -> list[bytes]:
    '''
      Génère les clées candidates pour déchiffrer le fichier à partir de la liste retournée par filtrer_dictionnaire_par_indices.
      
      Args:
        chemin_dictionnaire(str): le chemin du dictionnaire de mots de passes pour l'attaque par dictionnaire.
        
      Returns:
        list[bytes]: liste des clés candidates. 
    '''
    
    mots_de_passe_cible = self.__filtrer_dictionnaire_par_indices(chemin_dictionnaire)
    
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
  
  def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
    '''
      Tente de déchiffrer un fichier chiffré à partir d'une clé prise en paramètre. Elle retire d'abord l'IV puis tente de décrypter le reste du fichier à l'aide de la clé en retirant le padding et retournes les données originales (idéalement non chiffrées).
      
      Args:
        chemin_fichier_chiffre(str): chemin du fichier chiffre à déchiffrer
        cle_donnee(bytes): clé candidate pour le déchiffrement
      
      Returns:
        bytes: données déchiffrées
    '''
    try:
      with open(chemin_fichier_chiffre, "rb") as f:
        initialization_vector = f.read(16)
        donnees_chiffrees = f.read()
        
        # Validation de la taille de clé (AES-256 nécessite 32 bytes)
        if len(cle_donnee) != 32:
            raise ValueError("Erreur : La clé AES-256 doit faire 32 bytes")
        
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
        
        except ValueError as e:
          # Erreur de déchiffrement (clé incorrecte, padding invalide)
          # Ne pas retourner b"" si c'est une erreur de validation de taille
          if "doit faire 32 bytes" in str(e):
              raise
          return b""
        except Exception as e:
          # Erreur critique inattendue
          raise RuntimeError(f"Erreur critique lors du déchiffrement AES-CBC: {e}")
          
    except FileNotFoundError:
      raise