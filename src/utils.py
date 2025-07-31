import math

def valider_texte_dechiffre(texte):
    pass

def calculer_entropie_shannon(data):
   bytes = bytes(data)
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