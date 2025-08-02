from rich.console import Console
from rich.traceback import install
from rich.markdown import Markdown
from rich import print
from rich.prompt import Prompt
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

        self.prompt.ask("Veuillez choisir une option ",choices=["1","2","3","4","5","6"])


consoleInterface()