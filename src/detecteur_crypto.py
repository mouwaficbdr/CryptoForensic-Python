# Import des modules
import os
import time
from typing import List, Union
from pathlib import Path
# Import des modules d'analyse
from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.crypto_analyzer import CryptoAnalyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
from src.analyzers.fernet_analyzer import FernetAnalyzer

# Import des modules utilitaries
from src.utils import est_dechiffre

class ResultatAnalyse:
    """
        Classe représentant un résultat d'analyse.
    """
    def __init__(self, algo: str, cle: bytes, score_probabilite: float, texte_dechiffre: bytes, temps_execution: float = 0.0, nb_tentatives: int = 0):
        self.algo = algo
        self.cle = cle
        self.score_probabilite = score_probabilite
        self.texte_dechiffre = texte_dechiffre
        self.temps_execution = temps_execution
        self.nb_tentatives = nb_tentatives

class DetecteurCryptoOrchestrateur:
    """
            Classe principale qui centralise tout:
                -Lance l'analyse des fichiers et identifie l'algorithme probable,
                -Lance les attaques par dictionnaire,
                -Lance et coordonnes le processus de dechiffrement 
    """
    
    def __init__(self):
        """
        Initialisation de tous les modules d'analyse disponibles 
        """
        self.analyzers: dict[str, CryptoAnalyzer] = {
            "AES-CBC": Aes_Cbc_Analyzer(),
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

    def analyser_fichier_specifique(self, chemin_fichier_chiffre: str) -> ResultatAnalyse:
        """
        ANALYSE D'UN FICHIER SPÉCIFIQUE
        - Sélection du fichier à analyser
        - Identification automatique de l'algorithme
        - Affichage des scores de probabilité
        
        Args:
            chemin_fichier_chiffre(str): chemin du fichier chiffré à analyser
        
        Returns:
            ResultatAnalyse: résultat de l'analyse
        """
        debut_analyse = time.time()
        
        try:
            # Vérification de l'existence du fichier
            if not os.path.isfile(Path('data')/f"{chemin_fichier_chiffre}"):
                print("Erreur: Fichier non trouvé")
                return ResultatAnalyse("", b"", 0.0, b"", 0.0, 0)
            
            # Initialisation des variables
            algorithme_detecte = ""
            cle = b""
            score_probabilite = 0.0
            texte_dechiffre = b""
            nb_tentatives = 0
            
            # Parcours des algorithmes disponibles
            scores_algorithmes = {}
            for nom_algo, analyzer in self.analyzers.items():
                score = analyzer.identifier_algo(f"data/{chemin_fichier_chiffre}")
                scores_algorithmes[nom_algo] = score
                # print(f"{nom_algo}: score {score:.2f}")
                
                if score > 0.5:  # Seuil de confiance
                    algorithme_detecte = nom_algo
                    score_probabilite = score
                    # print(f"Algorithme détecté: {algorithme_detecte} (score: {score:.2f})")
                    break
            
            if not algorithme_detecte:
                print("Aucun algorithme correctement détecté ")
                temps_execution = time.time() - debut_analyse
                return ResultatAnalyse("", b"", 0.0, b"", temps_execution, nb_tentatives)
            
            temps_execution = time.time() - debut_analyse
            
            return ResultatAnalyse(algorithme_detecte, cle, score_probabilite, texte_dechiffre, temps_execution, nb_tentatives)
            
        except Exception as e:
            print(f"Erreur lors de l'analyse: {str(e)}")
            temps_execution = time.time() - debut_analyse
            return ResultatAnalyse("", b"", 0.0, b"", temps_execution, 0)
    
    def __tenter_dechiffrement_avec_dictionnaire(self, chemin_fichier: str, cles_candidates: list[bytes], analyzer: CryptoAnalyzer, resultat: ResultatAnalyse):
        for j, cle in enumerate(cles_candidates):
            resultat.nb_tentatives += 1
                            
            if j % 100 == 0:  # retour visuel tous les 100 essais
                print(f"   Tentative {j+1}/{len(cles_candidates)}...")
                            
            texte_dechiffre = analyzer.dechiffrer(chemin_fichier, cle)
            if texte_dechiffre and est_dechiffre(texte_dechiffre.decode('utf-8')) and len(texte_dechiffre) > 0:
                resultat.cle = cle
                resultat.texte_dechiffre = texte_dechiffre
                print(f"   Clé trouvée après {j+1} tentatives!")
                break
        else:
            print("Aucune clé valide trouvée")

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
            # Récupération des fichiers .enc
            fichiers_enc = [f for f in os.listdir(dossier_chiffres) if f.endswith(".enc")]
            
            if not fichiers_enc:
                print("Aucun fichier .enc trouvé dans le dossier")
                return []
            
            print(f"{len(fichiers_enc)} fichiers .enc détectés")
            print("\nANALYSE SÉQUENTIELLE DES FICHIERS")
            
            for i, fichier in enumerate(fichiers_enc, 1):
                print(f"\nFICHIER {i}/{len(fichiers_enc)}: {fichier}")
                
                chemin_fichier = os.path.join(dossier_chiffres, fichier)
                
                # Analyse du fichier
                resultat = self.analyser_fichier_specifique(fichier)
                
                # Tentative de déchiffrement si algorithme détecté
                if resultat.algo:
                    print(f"\nTENTATIVE DE DÉCHIFFREMENT")
                    
                    analyzer = self.analyzers[resultat.algo]
                    cles_candidates = analyzer.generer_cles_candidates(chemin_dictionnaire)
                    
                    if cles_candidates:
                        print(f"Test de {len(cles_candidates)} clés candidates...")
                        
                        self.__tenter_dechiffrement_avec_dictionnaire(chemin_fichier, cles_candidates, analyzer, resultat)
                    else:
                        print("   Aucune clé candidate générée")
                
                resultats.append(resultat)
                
                # retour visuel
                if resultat.algo:
                    print(f"{fichier}: {resultat.algo} (score: {resultat.score_probabilite:.2f})")
                else:
                    print(f"{fichier}: Aucun algorithme détecté")
            
            # Rapport de synthèse final
            generer_rapport_mission().generer_rapport_synthese(resultats, time.time() - debut_mission)
            
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

# print(DetecteurCryptoOrchestrateur().analyser_fichier_specifique(f"{os.path.abspath(os.curdir)}\\CryptoForensic-Python\\data\\mission2.enc"))
