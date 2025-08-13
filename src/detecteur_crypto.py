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
from rich.progress import Progress, TaskID
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
            "ChaCha20": ChaCha20_Analyzer(),
            "Blowfish": Blowfish_Analyzer(),
            "AES-GCM": Aes_Gcm_Analyzer(),
            "Fernet": FernetAnalyzer(),
        }
        self.missions_completees: list[dict[str, Union[str, list[ResultatAnalyse], float]]]  = []
        self.statistiques_globales: dict[str, Union[int, float]] = {
            "total_fichiers": 0,
            "fichiers_dechiffres": 0,
            "temps_total": 0.0,
            "tentatives_total": 0
        }
    
    def maj_progress_bar(self, sleep_avant: float, progress: Progress, task: TaskID, message: str, avance: float, sleep_apres: float):
        time.sleep(sleep_avant)
        progress.update(task_id=task, description=message, advance=avance)
        time.sleep(sleep_apres)
        
    def analyser_fichier_specifique(self, chemin_fichier_chiffre: str, progress : Progress, task, error:bool, nbr_opr_mission: int) -> List[ResultatAnalyse] :
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
        algorithme_potenciel = []
        try:
            # Vérification de l'existence du fichier
            avance = (100/(self._NBR_OPERATION_ANALYSE * nbr_opr_mission))
            # Done : Intégrer la progress bar -> step : Verification du chemin de fichier fourni
            self.maj_progress_bar(0.3, progress, task, "Verification du chemin de fichier fourni", avance * 0.3, 1) 
            
            if not os.path.isfile(Path('data')/f"{chemin_fichier_chiffre}"):
                
                # TODO : Intégrer la progress bar -> step : Verification du chemin de fichier fourni (Done)
                self.maj_progress_bar(0.3, progress, task, "Fichier non trouvé ❌ (Aborting...)", ((avance * self._NBR_OPERATION_ANALYSE) - avance * 0.3), 1) 
                
                error = True
                return [ResultatAnalyse("", b"", 0.0, b"", 0.0, 0)]
            
            # Initialisation des variables
            # TODO : Mise à jour de la progress bar -> step : Initialisation des utilitaires pour l'identification (Done)
            self.maj_progress_bar(0.5, progress, task, "Initialisation des utilitaires pour l'identification", avance*0.2, 1)

            cle = b""
            texte_dechiffre = b""
            nb_tentatives = 0
            
            # Parcours des algorithmes disponibles
            scores_algorithmes = {}
            
            # Pour les arrêts en cas d'erreurs, servira à upgrade la progress bar
            cumul_progress_avance = 0
            
            for nom_algo, analyzer in self.analyzers.items():
                avance_algo = avance/(len(self.analyzers)*3 * 0.5)
                
                # TODO : Mise à jour de la progress bar -> step : Utilisation de {algrorithme} pour déterminer le chiffrement (Done)
                self.maj_progress_bar(0.5, progress, task, f"Utilisation de {nom_algo} pour déterminer le chiffrement", avance_algo, 1)

                score = analyzer.identifier_algo(f"data/{chemin_fichier_chiffre}")
                scores_algorithmes[nom_algo] = score
                
                # TODO : Mise à jour de la progress bar -> step : Analyse des résultats d'identification (Done)
                self.maj_progress_bar(0.5, progress, task, "Analyse des résultats d'identification", avance_algo, 1)

                cumul_progress_avance += 2 * avance_algo
                
                if score >= 0.6 :  # Seuil de confiance
                    
                    algorithme_potenciel.append({
                        'algo': nom_algo,
                        'score': score
                    })
                    
                    # TODO : Mise à jour de la progress bar -> step : Détection réussie pour {algorithme} et préparation du rapport d'analyse (Done)
                    self.maj_progress_bar(1, progress, task, f"Elligibilité détectée pour {nom_algo}", avance_algo, 1)
                    
                else :
                    # TODO : Intégrer la progress bar -> step : Echec d'identification pour {algorithme} (Done)
                    self.maj_progress_bar(1, progress, task, f"Echec d'identification pour {nom_algo}", avance_algo, 1)

                    cumul_progress_avance += avance_algo
 
            if not algorithme_potenciel:
                print("Aucun algorithme correctement détecté ")
                temps_execution = time.time() - debut_analyse
                return [ResultatAnalyse("", b"", 0.0, b"", temps_execution, nb_tentatives, chemin_fichier_chiffre, 0)]
            
            temps_execution = time.time() - debut_analyse
            
            resultat : List[ResultatAnalyse]= []
            for item in algorithme_potenciel:
                resultat.append(ResultatAnalyse(item['algo'], cle, item['score'], texte_dechiffre, temps_execution, nb_tentatives, chemin_fichier_chiffre, 0))
            
            return resultat
        
        except Exception as e:
            print(f"Erreur lors de l'analyse: {str(e)}")
            temps_execution = time.time() - debut_analyse
            error = True
            return [ResultatAnalyse("", b"", 0.0, b"", temps_execution, 0, chemin_fichier_chiffre)]
    
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
                    
                    # TODO: New progress bar -> step: Analyse du fichier mission{i+1}.enc (Done)
                    task = progress.add_task(f"Analyse du fichier mission{i+1}.enc...", total=100)
                    time.sleep(0.5)
                    
                    chemin_fichier = os.path.join(dossier_chiffres, fichier)
                    
                    # Analyse du fichier
                    error = False
                    resultats_analyse = self.analyser_fichier_specifique(fichier, progress, task, error, self._NBR_OPERATION_MISSION)
                    cumul_avance : float = 0

                    print('analyzed')
                    # Tentative de déchiffrement si algorithme détecté
                    for resultat in resultats_analyse :
                        if resultat.algo:
                            avancement = (100/(self._NBR_OPERATION_MISSION * len(resultats_analyse)))
                            # TODO: MAJ de la progress bar -> step: Amorçage de la phase de déchiffrement (Done)
                            self.maj_progress_bar(0, progress, task, f"Amorçage de la phase de déchiffrement avec {resultat.algo}...", avancement * 0.5, 1)
                                                    
                            analyzer = self.analyzers[resultat.algo]
                            
                            # TODO: MAJ de la progress bar -> step: Récupération des clés candidates (Done)
                            self.maj_progress_bar(0, progress, task, f"Récupération des clés candidates pour {resultat.algo}...", avancement*0.5, 1)

                            cles_candidates = analyzer.generer_cles_candidates(chemin_dictionnaire)
                            cumul_avance += avancement
                            
                            if cles_candidates:
                                print(f"Test de {len(cles_candidates)} clés candidates pour {resultat.algo}...")
                                
                                # TODO: MAJ de la progress bar -> step: Test de déchiffrement (Done)
                                self.maj_progress_bar(0, progress, task, f"Test de déchiffrement pour {resultat.algo}...", avancement * 0.5, 3)
                            
                                error = self.__tenter_dechiffrement_avec_dictionnaire(chemin_fichier, cles_candidates, analyzer, resultat) 
                                
                                #Cas de déchiffrement réussi
                                if not error : 
                                    # TODO: MAJ de la progress bar -> step: Déchiffrement réussi pour {algorithme}
                                    self.maj_progress_bar(0.5, progress, task, f"Déchiffrement réussi pour {resultat.algo}", (100/self._NBR_OPERATION_MISSION) - cumul_avance , 2)
                                    
                                    resultat_final : ResultatAnalyse = resultat
                                    break
                                else : 
                                    self.maj_progress_bar(0.5, progress, task, f"Echec de déchiffrement pour {resultat.algo} ❌", avancement * 0.5, 2)
                            else :
                                # TODO: MAJ de la progress bar -> step: Abort et récupération des résultats d'analyse (Done)
                                self.maj_progress_bar(0, progress, task, f"Aucune clé candidate générée pour {resultat.algo}❌ (Aborting ...)", avancement, 3)
                                error = True
                    
                    resultats.append(resultat_final)
                    
                    # retour visuel
                    if resultat_final.algo:
                        # TODO: MAJ de la progress bar -> step: Finalsation et retour de résultats (Done)
                        self.maj_progress_bar(0, progress, task, "Finalisation et retour des résultats", 100, 3)
                        
                        print(f"{fichier}: {resultat_final.algo} (score: {resultat_final.score_probabilite:.2f})")
                        
                        message = "[bold green] Mission terminée. ✅[/bold green]\n\n" if not error else "[bold red] Mission terminée: Déchiffrement non concluant. ❌ [/bold red]\n\n"
                        Console().print(message)
                    else:
                        # TODO: MAJ de la progress bar -> step: Abort et récupération des résultats d'analyse (Done)
                        self.maj_progress_bar(0, progress, task, "Aborting et récupération des résultats d'analyse...", 100, 0.5)
                        Console().print(f"[bold yellow] Mission terminée: Aucun algorithme détecté. ⚠️[/bold yellow]\n\n")
                    
                    progress.remove_task(task)
                
                # Rapport de synthèse final
                with Progress() as progress :
                    task = progress.add_task("Préparation des rapports", total=100) # TODO: New progress bar -> step: Préparation des rapports (1 to 100%) (Done)
                    
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
                        progress.update(task, description="Mission complète effectuée.") # TODO: MAJ de la progress bar -> step: Mission complète effectuée (Done)

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


