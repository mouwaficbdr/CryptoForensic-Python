# Import des modules
import os
import time
from typing import List, Union
from pathlib import Path
from rich.progress import Progress
# Import des modules d'analyse
from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.crypto_analyzer import CryptoAnalyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
from src.analyzers.fernet_analyzer import FernetAnalyzer
from src.rapport_mission import rapport_mission
# Import des modules utilitaries
from src.utils import verifier_texte_dechiffre
from rich.progress import Progress
from rich.markdown import Markdown
from rich.console import Console
class ResultatAnalyse:
    """
        Classe représentant un résultat d'analyse.
    """
    def __init__(self, algo: str, cle: bytes, score_probabilite: float, texte_dechiffre: bytes, temps_execution: float = 0.0, nb_tentatives: int = 0, fichier: str ='', taux_succes: float = 0.0):
        self.algo = algo
        self.cle = cle
        self.score_probabilite = score_probabilite
        self.texte_dechiffre = texte_dechiffre
        self.temps_execution = temps_execution
        self.nb_tentatives = nb_tentatives
        self.fichier = fichier,
        self.taux_succes = taux_succes
class DetecteurCryptoOrchestrateur:
    """
            Classe principale qui centralise tout:
                -Lance l'analyse des fichiers et identifie l'algorithme probable,
                -Lance les attaques par dictionnaire,
                -Lance et coordonnes le processus de dechiffrement 
    """
    
    _NBR_OPERATION_MISSION = 4 
    _NBR_OPERATION_ANALYSE = 3
    
    def __init__(self):
        """
        Initialisation de tous les modules d'analyse disponibles 
        """
        self.analyzers: dict[str, CryptoAnalyzer] = {
            "AES-CBC-256": Aes_Cbc_Analyzer(),
            "CHACHA20": ChaCha20_Analyzer(),
            "BLOWFISH": Blowfish_Analyzer(),
            "AES-GCM": Aes_Gcm_Analyzer(),
            "FERNET": FernetAnalyzer(),
        }
        self.missions_completees: list[dict[str, Union[str, list[ResultatAnalyse], float]]]  = []
        self.statistiques_globales: dict[str, Union[int, float]] = {
            "total_fichiers": 0,
            "fichiers_dechiffres": 0,
            "temps_total": 0.0,
            "tentatives_total": 0
        }

    def analyser_fichier_specifique(self, chemin_fichier_chiffre: str, progress : Progress, task, error:bool, nbr_opr_mission: int) -> ResultatAnalyse:
        """
        ANALYSE D'UN FICHIER SPÉCIFIQUE
        - Sélection du fichier à analyser
        - Identification automatique de l'algorithme
        - Affichage des scores de probabilité
        
        Args:
            chemin_fichier_chiffre(str): chemin du fichier chiffré à analyser
            progress (Progress) : la progress bar à mettre à jour
            error(bool): nécessaire pour déterminer les erreurs et définir le message de final de la progress bar 
        Returns:
            ResultatAnalyse: résultat de l'analyse
        """
        debut_analyse = time.time()
        
        try:
            # Vérification de l'existence du fichier
            avance = (100/(self._NBR_OPERATION_ANALYSE * nbr_opr_mission))
            time.sleep(0.3) # Done : Intégrer la progress bar -> step : Verification du chemin de fichier fourni
            progress.update(task_id=task, description="Verification du chemin de fichier fourni", advance=avance * 0.3)
            time.sleep(1)
            
            if not os.path.isfile(Path('data')/f"{chemin_fichier_chiffre}"):
                time.sleep(0.3) # TODO : Intégrer la progress bar -> step : Verification du chemin de fichier fourni
                progress.update(task_id=task, description="Fichier non trouvé ❌ (Aborting...)", advance=((avance * self._NBR_OPERATION_ANALYSE) - avance * 0.3) )
                time.sleep(1)
                error = True
                return ResultatAnalyse("", b"", 0.0, b"", 0.0, 0)
            
            # Initialisation des variables
            time.sleep(0.5) # TODO : Mise à jour de la progress bar -> step : Initialisation des utilitaires pour l'identification
            progress.update(task_id=task, description="Initialisation des utilitaires pour l'identification", advance=avance*0.2)
            time.sleep(1)

            algorithme_detecte = ""
            cle = b""
            score_probabilite = 0.0
            texte_dechiffre = b""
            nb_tentatives = 0
            
            # Parcours des algorithmes disponibles
            scores_algorithmes = {}
            
            # Pour les arrêts en cas d'erreurs, servira à upgrade la progress bar
            cumul_progress_avance = 0
            
            for nom_algo, analyzer in self.analyzers.items():
                avance_algo = avance/(len(self.analyzers)*3 * 0.5)
                time.sleep(0.5) # TODO : Mise à jour de la progress bar -> step : Utilisation de {algrorithme} pour déterminer le chiffrement
                progress.update(task_id=task, description=f"Utilisation de {nom_algo} pour déterminer le chiffrement", advance=avance_algo)
                time.sleep(1)

                score = analyzer.identifier_algo(f"data/{chemin_fichier_chiffre}")
                scores_algorithmes[nom_algo] = score
                
                time.sleep(0.5) # TODO : Mise à jour de la progress bar -> step : Analyse des résultats d'identification
                progress.update(task_id=task, description="Analyse des résultats d'identification", advance=avance_algo)
                time.sleep(1)

                cumul_progress_avance += 2 * avance_algo
                
                if score > 0.9 :  # Seuil de confiance
                    time.sleep(1) # TODO : Mise à jour de la progress bar -> step : Détection réussie pour {algorithme} et préparation du rapport d'analyse
                    progress.update(task_id=task, description=f"Détection réussie pour {nom_algo} et préparation du rapport d'analyse", advance=((100/nbr_opr_mission) - cumul_progress_avance))
                    time.sleep(1)
                    
                    algorithme_detecte = nom_algo
                    score_probabilite = score
                    break
                else :
                    time.sleep(1) # TODO : Intégrer la progress bar -> step : Echec d'identification pour {algorithme}
                    progress.update(task_id=task, description=f"Echec d'identification pour {nom_algo}", advance=avance_algo)
                    time.sleep(1)
                    cumul_progress_avance += avance_algo
 
            if not algorithme_detecte:
                print("Aucun algorithme correctement détecté ")
                temps_execution = time.time() - debut_analyse
                return ResultatAnalyse("", b"", 0.0, b"", temps_execution, nb_tentatives, chemin_fichier_chiffre, 0)
            
            temps_execution = time.time() - debut_analyse
            
            return ResultatAnalyse(algorithme_detecte, cle, score_probabilite, texte_dechiffre, temps_execution, nb_tentatives, chemin_fichier_chiffre, 0)
            
        except Exception as e:
            print(f"Erreur lors de l'analyse: {str(e)}")
            temps_execution = time.time() - debut_analyse
            error = True
            return ResultatAnalyse("", b"", 0.0, b"", temps_execution, 0, chemin_fichier_chiffre)
    
    def __tenter_dechiffrement_avec_dictionnaire(self, chemin_fichier: str, cles_candidates: list[bytes], analyzer: CryptoAnalyzer, resultat: ResultatAnalyse):
        """
            Tente de déchiffrer un fichier avec les clés candidates et l'analyzer correspondant
            
            Args: 
                chemin_fichier(str) : chemin vers le fichier
                cles_candidates(list[bytes]) : les clés candidates retenus par le dossier de clés sur la base des indices
                analyzer(CryptoAnalyzer) : l'Analyzer correspondant à ce fichier
                resultat(ResultatAnalyse) : les résultats de l'analyse de fichier 
            
            Returns :
                bool : si une erreur est survenue ou non
        """
        for j, cle in enumerate(cles_candidates):
            resultat.nb_tentatives += 1
                                            
            # Déchiffrement et normalisation de l'affichage (évite les \x.. et caractères non imprimables)
            donnees = analyzer.dechiffrer(chemin_fichier, cle)
            texte_dechiffre = donnees.decode('utf-8', errors='ignore').replace('\x00', ' ')
            succes =  verifier_texte_dechiffre(texte_dechiffre)['taux_succes']
            
            if texte_dechiffre and succes > 60 and len(texte_dechiffre) > 0:
                resultat.cle = cle
                resultat.texte_dechiffre = texte_dechiffre
                resultat.taux_succes = succes
                print(f"Clé trouvée après {j+1} tentatives!")
                return False
        
        print("Aucune clé valide trouvée")
        return True

    def mission_complete_automatique(self, dossier_chiffres: str, chemin_dictionnaire: str) -> List[ResultatAnalyse]:
        """
        MISSION COMPLÈTE AUTOMATIQUE
        - Analyse des 5 fichiers séquentiellement
        - Tentatives de déchiffrement avec retour visuel
        - Rapport de synthèse final
        
        Args:
            dossier_chiffres(str): dossier contenant les fichiers chiffrés
        
        Returns:
            list[ResultatAnalyse]: liste des résultats d'analyse
        """

        debut_mission = time.time()
        resultats: list[ResultatAnalyse] = []
        try:
            with Progress() as progress :
                # Récupération des fichiers .enc
                fichiers_enc = [f for f in os.listdir(dossier_chiffres) if f.endswith(".enc")]
                
                if not fichiers_enc:
                    print("Aucun fichier .enc trouvé dans le dossier")
                    return []
                
                print(f"{len(fichiers_enc)} fichiers .enc détectés")
                print("\nANALYSE SÉQUENTIELLE DES FICHIERS")
                time.sleep(0.5) 
                for i, fichier in enumerate(fichiers_enc, 0):
                    print(f"\nFICHIER {i+1}/{len(fichiers_enc)}: {fichier}")
                    
                    # TODO: New progress bar -> step: Analyse du fichier mission{i+1}.enc
                    task = progress.add_task(f"Analyse du fichier mission{i+1}.enc...", total=100)
                    time.sleep(0.5)
                    
                    chemin_fichier = os.path.join(dossier_chiffres, fichier)
                    
                    # Analyse du fichier
                    error = False
                    resultat = self.analyser_fichier_specifique(fichier, progress, task, error, self._NBR_OPERATION_MISSION)
                    
                    # Tentative de déchiffrement si algorithme détecté
                    if resultat.algo:
                        # TODO: MAJ de la progress bar -> step: Amorçage de la phase de déchiffrement
                        progress.update(task, description="Amorçage de la phase de déchiffrement...", advance=((100/self._NBR_OPERATION_MISSION) * 0.5))
                        time.sleep(1)
                        
                        analyzer = self.analyzers[resultat.algo]
                        
                        # TODO: MAJ de la progress bar -> step: Récupération des clés candidates
                        progress.update(task, description="Récupération des clés candidates", advance=(100/self._NBR_OPERATION_MISSION)*0.5)
                        time.sleep(1)

                        cles_candidates = analyzer.generer_cles_candidates(chemin_dictionnaire)
                        
                        if cles_candidates:
                            print(f"Test de {len(cles_candidates)} clés candidates...")
                            # TODO: MAJ de la progress bar -> step: Test de déchiffrement
                            progress.update(task, description="Test de déchiffrement", advance=(100/self._NBR_OPERATION_MISSION))
                            time.sleep(3)
                        
                            error = self.__tenter_dechiffrement_avec_dictionnaire(chemin_fichier, cles_candidates, analyzer, resultat) 
                            
                        else:
                            # TODO: MAJ de la progress bar -> step: Abort et récupération des résultats d'analyse
                            progress.update(task, description="Aucune clé candidate générée ❌ (Aborting ...)", advance=(100/self._NBR_OPERATION_MISSION))
                            time.sleep(3)
                            error = True

                    
                    resultats.append(resultat)
                    
                    # retour visuel
                    if resultat.algo:
                        # TODO: MAJ de la progress bar -> step: Finalsation et retour de résultats
                        progress.update(task, description="Finalisation et retour des résultats", advance=(100/self._NBR_OPERATION_MISSION))
                        time.sleep(3)
                        
                        print(f"{fichier}: {resultat.algo} (score: {resultat.score_probabilite:.2f})")
                        
                        message = "[bold green] Mission terminée. ✅[/bold green]\n\n" if not error else "[bold red] Mission terminée: Déchiffrement non concluant. ❌ [/bold red]\n\n"
                        Console().print(message)
                    else:
                        progress.update(task, description="Aborting et récupération des résultats d'analyse...", advance=100)
                        time.sleep(0.5)  # TODO: MAJ de la progress bar -> step: Abort et récupération des résultats d'analyse
                        Console().print(f"[bold yellow] Mission terminée: Aucun algorithme détecté. ⚠️[/bold yellow]\n\n")
                    
                    progress.remove_task(task)
                
                # Rapport de synthèse final
                with Progress() as progress :
                    task = progress.add_task("Préparation des rapports", total=100) # TODO: New progress bar -> step: Préparation des rapports (1 to 100%)
                    
                    while not progress.finished :
                        progress.update(task, description="Préparation des rapports", advance=2)
                        time.sleep(0.2)
                    for i in range(len(fichiers_enc)) :
                        resultat = {
                            'algorithme': resultats[i].algo,
                            'fichier': resultats[i].fichier,
                            'cle': resultats[i].cle,
                            'tentatives': resultats[i].nb_tentatives,
                            'temps_execution': resultats[i].temps_execution,
                            'taux_succes': resultats[i].taux_succes,
                            'statut_succes' : 'Succès' if resultats[i].taux_succes > 60 else 'Echec',
                            'texte_dechiffre' : resultats[i].texte_dechiffre
                        }
                        rapport_mission().generer_rapport_synthese(resultat)
                        progress.update(task, description="Mission complète effectuée.") # TODO: MAJ de la progress bar -> step: Mission complète effectuée

                # Mise à jour des statistiques globales
                self.missions_completees.append({
                    "dossier": dossier_chiffres,
                    "resultats": resultats,
                    "temps_total": time.time() - debut_mission
                })
                
                return resultats
            
        except Exception as e:
            print(f"Erreur lors de la mission complète: {str(e)}")
            return []
        

    def attaque_dictionnaire_manuelle(self, chemin_fichier: str, algorithme_choisi: str, chemin_dictionnaire: str) -> ResultatAnalyse:
        """
            ATTAQUE PAR DICTIONNAIRE MANUELLE
        - Choix du fichier et de l'algorithme
        - Suivi en temps réel des tentatives
        - Affichage des résultats intermédiaires
        
        Args:
            chemin_fichier(str): chemin du fichier à attaquer
            algorithme_choisi(str): algorithme à utiliser
        
        Returns:
            ResultatAnalyse: résultat de l'attaque
        """
        
        
        debut_attaque = time.time()
        resultat = ResultatAnalyse("", b"", 0.0, b"", 0.0, 0)
        
        try:
            if algorithme_choisi not in self.analyzers:
                print(f"Algorithme {algorithme_choisi} non disponible")
                return resultat
            
            analyzer = self.analyzers[algorithme_choisi]
            
            # Vérification de l'algorithme
            score = analyzer.identifier_algo(chemin_fichier)
            resultat.score_probabilite = score
            resultat.algo = algorithme_choisi
            print(f"Score de confirmation: {score:.2f}")
            
            if score < 0.3:
                print("Score de confiance faible pour cet algorithme")
            
            # Génération des clés candidates
            print(f"Génération des clés candidates")
            cles_candidates = analyzer.generer_cles_candidates(chemin_dictionnaire)
            print(f"{len(cles_candidates)} clés candidates générées")
            
            # Attaque par dictionnaire
            
            self.__tenter_dechiffrement_avec_dictionnaire(chemin_fichier, cles_candidates, analyzer, resultat)
            
            
            temps_execution = time.time() - debut_attaque
            resultat.temps_execution = temps_execution
            print(f"Temps d'exécution: {temps_execution:.2f} secondes")
            
            return resultat
            
        except Exception as e:
            print(f"Erreur lors de l'attaque: {str(e)}")
            temps_execution = time.time() - debut_attaque
            return ResultatAnalyse("", b"", 0.0, b"", temps_execution, 0)
        
    def attaque_dictionnaire(self,chemin_fichier_chiffrer: str, algo : str, chemin_dico : str = "keys/wordlist.txt"):
        
        with Progress() as progress:
            analyzer = self.analyzers[algo]
            
            cle_candidates = analyzer.generer_cles_candidates(chemin_dico)

            with open(chemin_dico,'r') as d:
                dico = d.readlines()

            with open(f"data/{chemin_fichier_chiffrer}",'rb') as f :
                texte_chiffrer = f.read()

            task_id = progress.add_task("Testing...",total=len(cle_candidates))

            current_task = 0

            advance = 1


            while current_task < len(cle_candidates) :
                time.sleep(0.5)

                essai_dechiffrage = analyzer.dechiffrer(f"data/{chemin_fichier_chiffrer}", cle_candidates[current_task])
                
                if essai_dechiffrage != b"" :

                    progress.update(task_id,advance=len(cle_candidates) - current_task)

                    # Retourner un texte décodé/nettoyé pour affichage propre
                    return essai_dechiffrage.decode('utf-8', errors='ignore').replace('\x00', ' ')
                     
                current_task+=1

                progress.update(task_id,advance=advance)

        
        return "Aucune clé trouvé"

            # print("\n Process is done ...")


# print(DetecteurCryptoOrchestrateur().attaque_dictionnaire("mission5.enc","FERNET"))
