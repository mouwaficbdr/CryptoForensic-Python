from ..detecteur_crypto import CryptoAnalyzer
from ..utils import calculer_entropie

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