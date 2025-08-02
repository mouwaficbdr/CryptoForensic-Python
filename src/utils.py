import math

def valider_texte_dechiffre(texte):
    pass

def calculer_entropie(bytes) -> float:
   '''
      Calcul l'entropie (le désordre dans une suite de données) afin de déterminer le degré d'improbabilité d'une chaine de données.

      Args:
        bytes(bytes): La donnée brute contenue dans le fichier crypté.

      Returns:
        float: l'entropie calculée.
    '''
   entropie = 0
   proba_byte = 0
   for specifique_byte in bytes:
       i = 1
       for chaque_byte in bytes:
            if(chaque_byte == specifique_byte):
                i += 1
       proba_byte = 1 / i
       entropie +=  (proba_byte) * math.log(1/proba_byte, 8)
   return entropie