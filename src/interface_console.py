from rich.console import Console
from rich.traceback import install
from rich.markdown import Markdown
from rich import print
from rich.prompt import Prompt
from detecteur_crypto import Analyser_fichier_uniquement
from detecteur_crypto import Analyser_fichier_sequentiels
import time, os

install()

class consoleInterface:
    def __init__(self):
        # Dummy text for now
        self.console = Console()
        self.prompt = Prompt()
        self.default_menu()
        

    def console_size(self):
        size = os.get_terminal_size().columns
        return size
    def calc_center(self,text):
        center = (self.console_size() - len(text))/2
        return center
    def dynamiqueText(self,text,color):
        gap =0
        self.console.print('\n')
        while gap < self.calc_center(text):
            self.console.print(" ",end='')
            gap=gap+1

        for char in text:
            self.console.print(f"[{color}]{char}[/{color}]",end='')
            time.sleep(0.04)
        self.console.print('\n')

        

    def default_menu(self):
        self.console.clear()
        self.dynamiqueText("😈​ Bienvenue sur Forensic je suis Crypto votre assitant IA minimaliste🤖​ ","green")
        self.dynamiqueText("En quoi puis-je vous aider ? :","white")
        time.sleep(0.04)
        menuTag = Markdown("# Menu",style="blue")
        menuOption = Markdown("1. #### Analyse d'un fichier spécifique \n" \
                              "2. #### Mission complète automatique \n" \
                              "3. #### Attaque par dictionnaire manuelle \n" \
                              "4. #### Affichage des rapports \n" \
                              "5. #### Système d'aide intégré \n" \
                              "6. #### Quitter")
        self.console.print(menuTag,menuOption)
        time.sleep(0.04)

        choix = self.prompt.ask("Veuillez choisir une option ",choices=["1","2","3","4","5","6"])
        try:    
            if choix == "1":
                self.menu_1()
            elif choix == "2":
                self.menu_2()
            elif choix == "3":
                self.menu_3()
            elif choix == "4":
                self.menu_4()
            elif choix == "5":
                self.menu_5()
            elif choix == "6":
                self.menu_6()
                
            while choix > "6" or choix < "1":
                self.console.print("Veuillez entrer un nombre entre 1 et 6")
                choix = self.prompt.ask("Veuillez choisir une option ",choices=["1","2","3","4","5","6"])
        except ValueError:
            self.console.print("Veuillez entrer un nombre entre 1 et 6")
        except Exception as e:
            self.console.print(f"Une erreur est survenue : {e}")

    def menu_1(self):
        self.console.clear()
        self.dynamiqueText("Analyse d'un fichier spécifique","green")
        self.dynamiqueText("Veuillez entrer le chemin du fichier :","white")
        time.sleep(0.04)
        chemin_fichier = self.prompt.ask("Veuillez entrer le chemin du fichier : ")
        resultat = Analyser_fichier_uniquement(chemin_fichier)
        self.console.clear()
        self.dynamiqueText("Analyse en cours...","green")
        time.sleep(0.04)
        self.console.clear()
        self.dynamiqueText("Analyse terminée","green")
        time.sleep(0.04)
        self.default_menu()

    def menu_2(self):
        self.console.clear()
        self.dynamiqueText("Mission complète automatique","green")
        self.dynamiqueText("Veuillez entrer le chemin du dossier :","white")
        time.sleep(0.04)
        chemin_dossier = self.prompt.ask("Veuillez entrer le chemin du dossier : ")
        self.console.clear()
        self.dynamiqueText("Mission en cours...","green")
        time.sleep(0.04)
        self.console.clear()
        self.dynamiqueText("Mission terminée","green")
        time.sleep(0.04)
        self.default_menu()

    def menu_3(self):
        self.console.clear()
        self.dynamiqueText("Attaque par dictionnaire manuelle","green")
        self.dynamiqueText("Veuillez entrer le chemin du fichier :","white")
        time.sleep(0.04)
        chemin_fichier = self.prompt.ask("Veuillez entrer le chemin du fichier : ")
        self.console.clear()
        self.dynamiqueText("Attaque en cours...","green")
        time.sleep(0.04)
        self.console.clear()
        self.dynamiqueText("Attaque terminée","green")
        time.sleep(0.04)
        self.default_menu()

    def menu_4(self):
        self.console.clear()
        self.dynamiqueText("Affichage des rapports","green")
        time.sleep(0.04)
        self.default_menu()

    def menu_5(self):
        self.console.clear()
        self.dynamiqueText("Système d'aide intégré","green")
        time.sleep(0.04)
        self.default_menu()

    def menu_6(self):
        self.console.clear()
        self.dynamiqueText("Au revoir !","green")
        time.sleep(0.04)
        self.console.clear()
        self.console.exit()
        
consoleInterface()
