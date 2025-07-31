from ..crypto_analyzer import CryptoAnalyzer
from ..utils import calculer_entropie_shannon

class Aes_Cbc_Analyzer(CryptoAnalyzer): 
  
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
        
        entropie = calculer_entropie_shannon(donnees_chiffres)
        
        if entropie > 7.5: #Heuristique entropie élevée (L'entropie doit être supérieur à 7.5 pour confirmer le chiffrement robuste caractéristique des algos de chiffrement)
          probabilite += 0.4
        else:
          return 0.0
        
    except FileNotFoundError:
      print("Le fichier spécifié n'existe pas.")
      return 0.0
      
    return probabilite