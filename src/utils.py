import math
import string
import sys
import os


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
<<<<<<< HEAD
       proba_byte = 1 / i
       entropie +=  (proba_byte) * math.log(1/proba_byte, 8)
   return entropie
=======
        proba_byte = 1 / i
        entropie +=  (proba_byte) * math.log(1/proba_byte, 8)
    return entropie
>>>>>>> 267a282fa6e0765b0437b0aa3ef6139dc3453987


def est_dechiffre(texte:str) -> bool: 
    """
        Détermine si oui ou non une chaine a été déchiffrée
        
        Args: 
            texte(str): la chaine en supposée déchiffrée
        Returns: 
            bool: déchiffrée ou non
    """
    stats:dict=verifier_texte_dechiffre(texte)
    pourcent=0
    
    # Les caractères imprimables constituent 50% de la validation du déchiffrement
    if stats['imprimable'] > 70 :
        pourcent += 50
    
    # Le pourcentage de mots validés par les dictionnaires en constitue 30%
    if stats['p_mots_valide'] > 50 :
        pourcent += 30
    
    # Le respect de la ponctuation, les 20% restants
    if stats['ponctuation'] > 50 :
        pourcent += 20
    
    return True if pourcent > 70 else False
           
           
           

def verifier_texte_dechiffre(texte: str) -> dict[int, int, int, list, int]:
    """
        Verifie que le dechiffrement d'un message a bien été effectué sur la base de certains critères.

        Args: 
            texte(str): Le texte supposé déchiffré.

        Returns: 
            JSON(dictionnaire): statistiques sur le texte soit
            -le pourcentage de caratères imprimables,
            -le nombre de mots,
            -le pourcentage de mots valide, 
            -les mots non valides et 
            -le pourcentage de ponctuation respecté
    """

    #Statistiques sur le texte 
    
<<<<<<< HEAD
    stats={
            'imprimable':0,
            'nombre_mots':0,
            'p_mots_valide':0,
            'non_mots':[],
            'ponctuation_valide':0
        }
=======
    stats: dict = {
        'imprimable':0,
        'nombre_mots':0,
        'p_mots_valide':0,
        'non_mots':[],
        'ponctuation_valide':0
    }
>>>>>>> 267a282fa6e0765b0437b0aa3ef6139dc3453987
    
    #Verifier le pourcentage de caractères imprimables.
    
    for lettre in texte:
        if lettre.isprintable():
            stats['imprimable']+= 100/len(texte)
    
    # Traitement du texte brut pour obtenir une séquence distinct de pseudo-mot à cette étape séparé par des espaces
    
    tab='./:!\\}{_%*$£&#;,~"()[]=§|`^@'
    copy=texte
    for lettre in tab:
        copy=copy.replace(lettre, ' ')
    copy=copy.strip().split(' ')
    stats['nombre_mots']=len(copy)
    
    # Verifier que le texte est un mot anglais/francais 
    
    try:
        for mot in copy:
            trouve=False
            if mot == '': continue
            for syl in ['Fr', 'En']:
                chemin=f"{os.curdir}\\CryptoForensic-Python\\dico{syl}\\{mot[0]}.txt"
                
                with open(chemin, 'r') as f:
                    ligne=f.readline()
                    ligne=ligne.removesuffix('\n')
                    
                    while not trouve and ligne != "":
                        
                        if ligne == mot:
                            stats['p_mots_valide']+=100/len(copy)
                            print(stats['p_mots_valide'], mot)
                            trouve=True
                            break
                        
                        ligne=f.readline()
                        ligne=ligne.removesuffix('\n')
                        
                f.close()
                
                if trouve : break
                
            if not trouve : 
                stats['non_mots'].append(mot)
                    
    except Exception:
        tb=sys.exception().__traceback__
        raise Exception().with_traceback(tb)
        

    #Verifier la structure de ponctuation.

    points='.?!;,'
    nbr_ponct=0
    for point in points :
        nbr_ponct+=texte.count(point)
    for point in points :
        partition= texte.partition(point)
        if partition[2].startswith(' ') :
            if (point in '?!.' and partition[2].lstrip()[0].isupper()) or (point in ';,' and partition[2].lstrip()[0].islower()):
                stats['ponctuation_valide']+=100/nbr_ponct
        
    for key in stats:
        print(key)
        if isinstance(stats[key], float):
            stats[key]=round(stats[key], 2)
    
    return stats
    

def rangerDico():
    """
        Fonction utilitaire de rangement du dictionnaire anglais téléchargé
    """
    i=0
    compte = 0
    # Ouverture du grand dictionnaire.
    with open(f"{os.path.abspath(os.curdir)}\\words_alpha.txt",'r') as f:
        while i<26:
            # Définition du chemin vers le fichier de chaque mot en fonction de l'alphabet.
            chemin=f"{os.curdir}\\CryptoForensic-Python\\dicoEn\\{string.ascii_lowercase[i]}.txt"
            with open(chemin, 'a') as fichier:
                #Ecriture dans le fichier.
                fichier.write(string.ascii_lowercase[i]+'\n')
                while 1 :
                    ligne=f.readline()
                    if ligne.startswith(string.ascii_lowercase[i]) or ligne.startswith('y'):
                        fichier.write(ligne) 
                        compte += 1 
                    else :
                        break
            # Fermeture du fichier apres écriture du dernier mot.
            fichier.close()
            i+=1
    print(compte)   
    
# rangerDico()         

print(verifier_texte_dechiffre('neither#nor avec, ded_caractère a'))
