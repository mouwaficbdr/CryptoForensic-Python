from datetime import date, datetime
import os
from pathlib import Path
class rapport_mission():
    
    def __init__(self):
        pass
    
    def generer_rapport_synthese(self, resultats_de_mission:dict)->None:
        """
            Retourne le rapport de mission effectué.
            Args: 
                resultats_de_mission(dict{algorithme, fichier, cle, tentatives, temps_execution, taux_succes, texte_dechiffre}): les résultats de l'opération de déchiffrement du fichier
            Returns:
                str: le rapport
        """
        
        equivalence=['AES-CBC-256', 'CHACHA20', 'BLOWFISH', 'AES-GCM', 'FERNET']
        
        try :
            rapport= f"RAPPORT DE SYNTHESE DU {date.today().strftime("%d/%m/%y")} à {str(datetime.now().time()).split('.')[0]}\n " f"Mission {equivalence.index(resultats_de_mission['algorithme'].upper()) + 1}: {resultats_de_mission['algorithme'].upper()} \n I - Statistiques relatives à l'analyse du fichier\n" f"-Fichier crypté par cet algorithme: {resultats_de_mission['fichier']}\n" f"-Clé de déchiffrement identifiée: {resultats_de_mission['cle']} \n" f"-Nombre de tentatives: {resultats_de_mission['tentatives']} \n" f"-Temps d'exécution: {resultats_de_mission["temps_execution"]} \n II - Résultats obtenus\n" f"-Taux réussite du déchiffrement: {resultats_de_mission['taux_succes']}({resultats_de_mission['statut_succes']})\n" f"-Texte déchiffré: {resultats_de_mission['texte_dechiffre']} \n\n"
            
            # Ecriture du rapport dans le fichier rapport.txt pour les affichage ultérieurs
            chemin = Path(f"rapport_mission.txt")
            with open(chemin, 'a') as f:
                f.write(rapport.replace('\n', '~'))
            f.close()
            print(rapport)
            
            return 
        except (KeyError, ValueError):
            print("Une erreur s'est produite.") 
            return
        
    
    
    def recuperer_ancien_rapport(self, base_date:str)->list|str:
        """
            Récupère un/les ancien(s) rapport(s) dans le fichier rapport.txt
            
            Args: 
                base_date(str): la date à laquelle le/les rapport(s) a/ont été émis
            Returns:
                list|str: les rapports s'ils existent.


        """
        rapports=[]
        try:
            chemin = Path(f"rapport_mission.txt")
            with open(chemin, 'r') as f:
                for line in f:
                    if line.find(base_date) != -1:
                        rapports.append(line.replace('~', '\n'))
                f.close()
                return rapports if rapports else False
        except FileNotFoundError:
            print('Fichier non trouvé')
            
# print(generer_rapport_mission().generer_rapport_synthese({
#     'algorithme':'CHACHA20', 
#     'fichier': 'mission1.enc',
#     'cle':'PK7',
#     'tentatives':'127',
#     'temps_execution':"368s",
#     'taux_succes': "97%",
#     'statut_succes':'Succès',
#     'texte_dechiffre':'Je suis là!'
# }))

# print(generer_rapport_mission().recuperer_ancien_rapport("05/08/25")[0])
