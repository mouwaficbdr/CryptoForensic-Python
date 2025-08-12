import re
import math
from rich.console import Console
from rich.traceback import install
from rich.markdown import Markdown
from rich import print
from rich.text import Text
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress
from pathlib import Path
# from tqdm import tqdm
# from detecteur_crypto import Analyser_fichier_uniquement
# from detecteur_crypto import Analyser_fichier_sequentiels
from .detecteur_crypto import DetecteurCryptoOrchestrateur
from .rapport_mission import rapport_mission
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
            time.sleep(0.02)
        self.console.print('\n')

        

    def default_menu(self):
        self.console.clear()
        self.dynamiqueText("😈​ Bienvenue sur Forensic je suis Crypto votre assitant IA minimaliste 🤖​ ","green")
        self.dynamiqueText("En quoi puis-je vous aider ? :","white")
        time.sleep(0.02)
        menuTag = Markdown("# Menu",style="blue")
        menuOption = Markdown("1. #### Analyse d'un fichier spécifique \n" \
                              "2. #### Mission complète automatique \n" \
                              "3. #### Attaque par dictionnaire manuelle \n" \
                              "4. #### Affichage des rapports \n" \
                              "5. #### Système d'aide intégré \n" \
                              "6. #### Quitter")
        self.console.print(menuTag,menuOption)
        time.sleep(0.02)

        choix = self.prompt.ask("Veuillez choisir une option ", choices=["1","2","3","4","5","6"])
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
        except ValueError:
            self.console.print("Veuillez entrer un nombre entre 1 et 6")
        except Exception as e:
            self.console.print(f"Une erreur est survenue : {e}")

    def menu_1(self):
        self.console.clear()
        self.dynamiqueText("Analyse d'un fichier spécifique","green")
        self.dynamiqueText("Veuillez entrer le chemin du fichier","yellow")
        fichier = self.prompt.ask("")
        time.sleep(0.02)
        self.dynamiqueText("Analyse en cours...","green")
        with Progress() as progress :
            
            task=progress.add_task(f"Analyse du {fichier}", total=100)
            error = False 
            data = DetecteurCryptoOrchestrateur().analyser_fichier_specifique(fichier, progress, task, error, 1)
            if data.algo :
                print(f"\n[bold]Algorithme détecté[/bold] : [yellow]{data.algo}[/yellow]")
                print(f"[bold]Score de probabilité[/bold] : [green]{data.score_probabilite}[/green]")
                message = "[bold green] Analyse terminée. ✅[/bold green]" if not error else "[bold red] Mission terminée: Analyse non concluante. ❌ [/bold red]\n"
                self.console.print(message)
            else :
                self.console.print("[bold yellow] Analyse terminée: Aucun algorithme détecté. ⚠️[/bold yellow]")
            progress.remove_task(task)

        print(f"[bold]Temps d'éxécution[/bold] : [green]{round(data.temps_execution,4)}[/green] s")
        esc=input("Veuillez appuyer sur la touche entrer pour retourner au menu principal")
        if esc=="":
            self.default_menu()
        else : self.default_menu()

    def menu_2(self):
        self.console.clear()
        self.dynamiqueText("Mission complète automatique","green")
        self.dynamiqueText("Veuillez entrer le chemin du dossier :","white")
        time.sleep(0.02)
        
        chemin_dossier = self.prompt.ask("Veuillez entrer le chemin du dossier : ")
        resultat = DetecteurCryptoOrchestrateur().mission_complete_automatique(chemin_dossier, "keys/wordlist.txt")
        print(line for line in resultat)
        # self.console.clear()
        self.dynamiqueText("Mission en cours...","green")
        time.sleep(0.02)
        # self.console.clear()
        self.dynamiqueText("Mission terminée","green")
        
        esc=input("Veuillez appuyer sur la touche entrer pour retourner au menu principal")
        time.sleep(0.02)
        
        if esc=="":
            self.default_menu()
        else : self.default_menu()
        
        # self.default_menu()

    def menu_3(self):
        self.console.clear()
        self.dynamiqueText("Attaque par dictionnaire manuelle","green")
        self.dynamiqueText("Veuillez entrer le nom du fichier sur lequel l'attaque doit être effectuée","white")
        # time.sleep(0.02)
        pad=0
        while pad < self.calc_center(":missionN.enc"):
            print(" ",end="")
            pad+=1
        chemin_fichier = self.prompt.ask("")

        algo = self.prompt.ask("Veuillez saisir l'un des algorithmes suivant pour le déchiffrage",choices=["AES-CBC-256","CHACHA20","BLOWFISH","AES-GCM","FERNET"]).upper()

        self.dynamiqueText("Attaque en cours...","green")
        # time.sleep(0.02)
        # self.console.clear()
        print(DetecteurCryptoOrchestrateur().attaque_dictionnaire(chemin_fichier,algo))

        self.dynamiqueText("Attaque terminée","green")

        print("Veuillez saisir la touche ' Entrer ' afin de retourner au menu principale",end='')
        esc = input("")

        if esc == "":
            self.default_menu()
        else :
            self.default_menu()


    def menu_4(self):
        self.console.clear()
        self.dynamiqueText("Affichage des rapports","green")
        time.sleep(0.02)
        date = input("Quel est la date du rapport que vous souhaitez? Entrez 'all' pour tous les rapports. (format: jj/mm/aa): ")
        
        rapports = []
        if date == "all" :
            with open("rapport_mission.txt",'r') as f :
                rapports = f.readlines()
            f.close()
        elif re.match(r"\d+/\d+/\d+", date) :
            rapports = rapport_mission().recuperer_ancien_rapport(date)
            
        if rapports :
            for rapport in rapports:
                print(f"\n{rapport.replace('~', '\n')}")
        else :
            self.console.print(Markdown('#### Aucun rapport trouvé.'))
        
        time.sleep(0.03)
        esc = input('Veuillez appuyez sur la touche entrer pour continuer')
        if esc=="": 
            self.default_menu()

    def menu_5(self):
        self.console.clear()
        self.dynamiqueText("Système d'aide intégré","green")
        title = Markdown("# Guide d'utilisation",style="yellow bold")
        contexte_title = Markdown("### 📋 Contexte de la Mission",style="green")
        contexte= Markdown("### Vous êtes un analyste en cybersécurité travaillant pour une agence gouvernementale. Lors d'une opération d'investigation, votre équipe a intercepté 5 fichiers chiffrés contenant des informations cruciales. Votre mission est d'identifier l'algorithme de chiffrement utilisé pour chaque fichier, de découvrir la clé de déchiffrement, puis d'extraire le contenu secret.\n" \
        "### Les criminels ont utilisé 5 algorithmes de chiffrement symétrique différents pour protéger leurs communications. Votre expertise en cryptanalyse sera mise à l'épreuve pour déchiffrer ces messages et découvrir les secrets qu'ils contiennent.\n")

        mission_table = Table(title = "Missions Accomplies",style="",show_lines= True,leading=1)
        mission_table.add_column("Intitulé",style="violet",justify="center")
        mission_table.add_column("Fichier cible",style="red",justify="center")
        mission_table.add_column('Indice',style="yellow",justify="center")
        mission_table.add_column("Défi",style="green",justify="center")

        mission_table.add_row("AES-256-CBC","mission1.enc","La clé est liée à une ville française célèbre et une année olympique"," Identifier l'algorithme AES en mode CBC et récupérer la clé par attaque dictionnaire")
        mission_table.add_row("ChaCha20","mission2.enc","Combinaison d'une année récente et d'un mot de passe anglais commun","Reconnaître le chiffrement de flux moderne ChaCha20")
        mission_table.add_row("Blowfish","mission3.enc","Nom d'un algorithme de hachage populaire suivi de chiffres","Détecter l'algorithme Blowfish et ses spécificités")
        mission_table.add_row("AES-256-GCM","mission4.enc","Acronyme d'une organisation internationale + année courante","Identifier le mode authentifié GCM et gérer l'authentification")
        mission_table.add_row("Fernet","mission5.enc","Phrase française simple encodée, liée à notre domaine d'étude","Reconnaître le format Fernet et sa structure particulière")

        chemin = Path().cwd()/'guideUtilisation.txt'
        f = open(chemin,'r')
        algo_docs = Markdown(f.read())
        f.close()

        process= Markdown("### Processus d'usage logiciel",style="purple underline")
        intro = Markdown("Comme vous l'avez probablement remarqué le menu de ce logiciel est composé de 06 options dont 04 principales :")
        usage_guide_1 = Markdown("1. ### Analyse d'un fichier spécifique \n",style="black on white")
        analysis_1 = Markdown("    Cette option a pour but de traiter un fichier crypter ( prise en charge des '.enc' exceptionnellement ) afin d'identifier l'algorithme \n\n" \
                            "    de cryptage qui lui a été appliqué ainsi que le score de probabilité de chaque algorithme de cryptage cité ci-dessus \n\n")
        usage_guide_2 = Markdown("2. ### Mission complète automatique \n",style="black on white")
        analysis_2 = Markdown("     Cette option permet de traiter les 05 missions de façon séquentielle afin de ressortir de chacune d'entre elle :\n\n" \
                            "          -la clé de crypatage\n\n" \
                            "          -le message déchiffrer\n\n" \
                            "     A la fin des traitement un synthèse finale est générée sur l'état des Test effectué")

        usage_guide_3 = Markdown("3. ### Attaque par dictionnaire manuelle",style="black on white")
        analysis_3=Markdown("       En optant pour cette option vous aurez à sélectionner le fichier que vous souhaitez décrypté et par suite l'algorithme de décryptage que vous voudiez appliquer.\n" \
                            "       Vous aurez dun suivez en tempps réel de l'evolution des tentatives ainsi que l'affichage du résultat obtenu")

        usage_guide_4 = Markdown("4. ### Affichage des rapports \n",style="black on white")
        analysis_4 =Markdown("      Cette option vous permettra d'oberver les rapports des différents tests de décryptages effectués au cours de l'utilisation de ce logiciel")

        final = Markdown("# 😁​ Merci d'utiliser notre logiciel 👾​ et bonne continuation ( **Appuyez sur la touche Enter pour retourner au menu principal** )",style="yellow")

        # print(title,contexte_title,contexte,mission_table,algo_docs,process,intro,usage_guide_1,analysis_1,usage_guide_2,analysis_2,usage_guide_3,analysis_3,usage_guide_4,analysis_4,final)
        # escape = input('')
        guides = [title,contexte_title,contexte,mission_table,algo_docs,process,intro,usage_guide_1,analysis_1,usage_guide_2,analysis_2,usage_guide_3,analysis_3,usage_guide_4,analysis_4,final]

        for guide in guides:
            print(guide)
            print("\n") 

        escape= input('')
        if escape != None:
            self.default_menu()

    def menu_6(self):
        self.console.clear()
        self.dynamiqueText("😄​ Merci pour votre visite et à la revoyure 👋​ !","yellow")
        time.sleep(2)
        self.console.clear()
            
# consoleInterface()

if __name__ == "__main__":
    # Lancer l'interface console directement: python -m src.interface_console
    install()
    consoleInterface()
