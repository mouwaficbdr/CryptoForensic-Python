from datetime import date
import os

class generer_rapport_mission():
    
    def __init__(self):
        pass
    
    def generer_rapport_synthese(self, resultats_de_mission:dict)->None:
        """
            Retourne le rapport de mission effectué.
            Args: 
                resultats_de_mission(dict): les résultats de l'opération de déchiffrement du fichier
            Returns:
                str: le rapport
        """
        
        equivalence=['AES-CBC-256', 'CHACHA20', 'BLOWFISH', 'AES-GCM', 'FERNET']
        
        try :
            rapport= f"RAPPORT DE SYNTHESE DU {date.today().strftime("%d/%m/%y")}\n " 
            +  f"Mission {equivalence.index(resultats_de_mission['algorithme'].toupper()) + 1}: {resultats_de_mission['algorithme'].toupper()} \n" 
            +  "I - Statistiques relatives à l'analyse du fichier\n"
            + f"Fichier crypté par cet algorithme: {resultats_de_mission['fichier']}\n"
            + f"Clé de déchiffrement identifiée: {resultats_de_mission['cle']} \n"
            + f"Nombre de tentatives: {resultats_de_mission['tentatives']} \n"
            + f"Temps d'exécution: {resultats_de_mission["temps_execution"]} \n"
            +  "II - Résultats obtenus"
            + f"Taux réussite du déchiffrement: {resultats_de_mission['taux_succes']}({resultats_de_mission['statut_succes']})\n"
            + f"Texte déchiffré: {resultats_de_mission['texte_dechiffre']} \n"
            
            # Ecriture du rapport dans le fichier rapport.txt pour les affichage ultérieurs
            with open(f"{os.path.abspath(os.curdir)}\\CryptoForensic-Python\\rapport_mission.txt", 'a') as f:
                f.write(rapport.replace('\n', '~'))
                f.close()
                
            return rapport
        except (KeyError, ValueError):
            print("Une erreur s'est produite.")
        
        return rapport
    
