import math
import string
import sys
from typing import Any, Dict, List, TypedDict

class StatsDict(TypedDict):
    imprimable: float
    nombre_mots: int
    p_mots_valide: float
    non_mots: List[str]
    ponctuation_valide: int

def calculer_entropie(bytes: bytes) -> float:
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

        

def verifier_texte_dechiffre(texte: str) -> Dict[str, Any]:
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
    
    stats: dict = {
        'imprimable':0,
        'nombre_mots':0,
        'p_mots_valide':0,
        'non_mots':[],
        'ponctuation_valide':0
    }
    
    if not texte:
        return stats

    #Verifier le pourcentage de caractères imprimables.
    stats['imprimable'] = int(sum(1 for char in texte if char.isprintable()) / len(texte) * 100)

    # Traitement du texte brut pour obtenir une séquence distincte de pseudo-mot à cette étape séparé par des espaces
    
    tab='./:!\\}{_%*$£&#;,~"()[]=§|`^@?'
    copy=texte
    for lettre in tab:
        copy=copy.replace(lettre, ' ')
    mots = [mot for mot in copy.strip().split(' ') if mot]
    stats['nombre_mots']=len(mots)
    
    # Verifier que le chaque mot du texte est un mot anglais/francais 
    
    try:
        mots_valides = 0
        for mot in mots:
            trouve=False
            if not mot: continue
            
            first_char = mot[0].lower()
            
            for syl in ['Fr', 'En']:
                chemin=f"dico{syl}/{first_char}.txt"
                try:
                    with open(chemin, 'r', encoding='latin-1') as f: 
                        for ligne in f:
                            if ligne.strip() == mot:
                                mots_valides += 1
                                trouve=True
                                break
                except FileNotFoundError:
                    continue
                
                if trouve : break
                
            if not trouve : 
                stats['non_mots'].append(mot)
        if mots:
            stats['p_mots_valide'] = round((mots_valides / len(mots)) * 100, 2)
        else:
            stats['p_mots_valide'] = 0.0
                    
    except Exception:
        tb=sys.exception().__traceback__
        raise Exception().with_traceback(tb)
        

    #Verifier la structure de ponctuation.

    points='.?!;,'
    count = 0
    for i, char in enumerate(texte):
        if char in points:
            if (i == len(texte) - 1) or (texte[i+1] == ' '):
                count += 1
    stats['ponctuation_valide'] = count
    
    return stats
    

def rangerDico() -> None:
    """
        Fonction utilitaire de rangement du dictionnaire anglais téléchargé
        Pour effectuer des tests
    """
    i=0
    compte = 0
    # Ouverture du grand dictionnaire.
    try :
        # Utilisation de Path pour un chemin portable
        words_path = Path.cwd() / "words_alpha.txt"
        with open(words_path,'r') as f:
            while i<26:
                # Définition du chemin vers le fichier de chaque mot en fonction de l'alphabet.
                dico_path = Path.cwd() / "dicoEn" / f"{string.ascii_lowercase[i]}.txt"
                with open(dico_path, 'a') as fichier:
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
    except FileNotFoundError: 
        print('Fichier non trouvé.')
# rangerDico()         

