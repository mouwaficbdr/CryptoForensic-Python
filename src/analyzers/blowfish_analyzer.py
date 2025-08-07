from ..detecteur_crypto import CryptoAnalyzer
from ..utils import calculer_entropie
import hashlib

class Blowfish_Analyzer(CryptoAnalyzer):
  '''Détermine si l'algo blowfish est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
  
    Cette classe a trois méthodes:
    - identifier_algo: Détermine si l'algo de chiffrement utilsé sur le fichier chiffré qui lui est passé en paramètre est blowfish.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
    

  '''
  def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
    '''
      Détermine la probabilité que l'algo de chiffrement utilisé soit blowfish en:
      
      - vérifiant la présence d'un IV à l'en-tête (taille fichier > 8 octets) et que la taille du fichier est un multiple de 8 (blocs de 8 octets pour l'algo blowfish)
      - calculant l'entropie des données chiffrées
      - calculant l'entropie des sous blocs
      
      Args:
        chemin_fichier_chiffre(str): Le chemin du fichier chiffré à traiter (mission1.enc).
      
      Returns:
        float: probabilité calculée.
    '''
    
    score = 0.0
    try: 
      with open(chemin_fichier_chiffre, "rb") as f:
        contenu_fichier: bytes = f.read()
        taille_totale = len(contenu_fichier)
        TAILLE_IV = 8
        
        # Heuristique 1 : Vérification de la taille (le critère le plus important)
        if taille_totale > TAILLE_IV and taille_totale % 8 == 0:
          score += 0.4
          
          donnees_chiffrees = contenu_fichier[TAILLE_IV:]
          
          # Heuristique 2 : Vérification de l'entropie globale
          entropie_globale = calculer_entropie(donnees_chiffrees)
          if entropie_globale > 7.5:
            score += 0.3
            
            # Heuristique 3 : Vérification du "pattern Blowfish" (entropie par sous-blocs)
            taille_donnees = len(donnees_chiffrees)
            moitie = taille_donnees // 2
            
            entropie_moitie1 = calculer_entropie(donnees_chiffrees[:moitie])
            entropie_moitie2 = calculer_entropie(donnees_chiffrees[moitie:])
            
            if entropie_moitie1 > 7.5 and entropie_moitie2 > 7.5:
              score += 0.3
              
    except FileNotFoundError:
      return 0.0    
    
    return score


  def __filtrer_dictionnaire_par_indice(self, chemin_dictionnaire: str) -> list[str]:
    """
    Filtre le dictionnaire en se basant sur les indices de la mission 3.
    L'indice pointe vers un format de clé "sha + nombre + chiffres simples".
    
    Args:
      chemin_dictionnaire(str): Le chemin vers le fichier de dictionnaire.
    
    Returns:
      list[str]: Une liste de mots de passe filtrés.
    """
    mots_filtres: list[str] = []
    
    # Indices pour le préfixe et le suffixe
    prefixes = ("sha256", "sha384", "sha512", "sha1") 
    suffixes = ("123", "456", "789")
    
    try:
      with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
        for ligne in f:
          mot = ligne.strip()
          
          # Vérifie si le mot commence par un préfixe et se termine par un suffixe
          if mot.startswith(prefixes) and mot.endswith(suffixes):
            mots_filtres.append(mot)
            
    except FileNotFoundError:
      print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
      return []
    
    return mots_filtres

  def generer_cles_candidates(self, chemin_dictionnaire: str) -> list[bytes]:
          """
          Génère une liste de clés candidates pour le déchiffrement.
          Les candidats incluent les mots de passe directs, leur hash MD5 et leur hash SHA1.
          
          Args:
              chemin_dictionnaire(str): Le chemin vers le fichier de dictionnaire.
          
          Returns:
              list[bytes]: Une liste des clés candidates sous forme d'octets.
          """
          cles_candidates: list[bytes] = []
          # Utilisation de la méthode privée pour filtrer les mots
          mots_de_passe_cible = self.__filtrer_dictionnaire_par_indice(chemin_dictionnaire)
          
          for mot in mots_de_passe_cible:
              mot_en_bytes = mot.encode("utf-8")
              
              # 1. Ajouter le mot de passe direct comme clé candidate
              cles_candidates.append(mot_en_bytes)
              
              # 2. Hachage MD5 et ajout à la liste (en bytes)
              hash_md5 = hashlib.md5(mot_en_bytes).digest()
              cles_candidates.append(hash_md5)
              
              # 3. Hachage SHA1 et ajout à la liste (en bytes)
              hash_sha1 = hashlib.sha1(mot_en_bytes).digest()
              cles_candidates.append(hash_sha1)
          
          return cles_candidates