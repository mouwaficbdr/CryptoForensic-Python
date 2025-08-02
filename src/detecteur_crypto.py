# Import des modules
import os

# Import des modules d'analyse
from .analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer

class ResultatAnalyse:
    """
        Classe représentant un résultat d'analyse.
    """
    def __init__(self, algo: str, cle: bytes, texte_dechiffre: bytes):
        self.algo = algo
        self.cle = cle
        self.texte_dechiffre = texte_dechiffre

class DetecteurCryptoOrchestrateur:
    """
            Classe principale qui centralise tout:
                -Lance l'analyse des fichiers et identifie l'algorithme probable,
                -Lance les attaques par dictionnaire,
                -Lance et coordonnes le processus de dechiffrement 
    """
    
    def __init__(self):
        """
        Initialisation de tous les modules d'analyse disponibles (AES-CBC) pour le moment
        """
        self.analyzers = {
            "AES-CBC": Aes_Cbc_Analyzer(),
        }

    def Analyser_fichier_uniquement(self, chemin_fichier_chiffre: str) -> ResultatAnalyse:
        """
            Analyse un seul fichier chiffré et retourne le résultat de l'analyse.
            
            Args:
                chemin_fichier_chiffre(str): chemin du fichier chiffré à analyser
            
            Returns:
                ResultatAnalyse: résultat de l'analyse
        """
        try:
            #Initialisation des variables
            algorithme_detecte = ""
            cle = b""
            texte_dechiffre = b""
            
            #Parcours des algorithmes disponibles
            for nom_algo, analyzer in self.analyzers.items():
                score_probabilite = analyzer.identifier_algo(chemin_fichier_chiffre)  #  Retourne un float
                print(f"{nom_algo}: score {score_probabilite:.2f}")
                
                if score_probabilite > 0.5:  # Comparaison correcte avec le seuil
                    algorithme_detecte = nom_algo  # Stockage du nom de l'algorithme
                    print(f"Algorithme détecté: {algorithme_detecte} (score: {score_probabilite:.2f})")
                    
                    # Génération des clés candidates
                    cles_candidates = analyzer.generer_cles_candidates("dicoEn")
                    print(f"{len(cles_candidates)} clés candidates générées")
                    
                    # Test de déchiffrement avec la première clé (pour l'exemple)
                    if cles_candidates:
                        texte_dechiffre = analyzer.dechiffrer(chemin_fichier_chiffre, cles_candidates[0])
                        if texte_dechiffre:
                            cle = cles_candidates[0]
                            print("Déchiffrement réussi avec la première clé!")
                        else:
                            print("Déchiffrement échoué avec la première clé")
                    break
            
            if not algorithme_detecte:
                print("Aucun algorithme détecté avec confiance suffisante")
            
            return ResultatAnalyse(algorithme_detecte, cle, texte_dechiffre)
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier {chemin_fichier_chiffre}: {str(e)}")
            return ResultatAnalyse("", b"", b"")
    
    
    def Analyser_fichiers_sequentiels(self, dossier_chiffres: str) -> list[ResultatAnalyse]:
        """
            Analyse plusieurs fichiers chiffrés dans un dossier et retourne les résultats de l'analyse.
            
            Args:
                dossier_chiffres(str): dossier contenant les fichiers chiffrés à analyser
            
            Returns:
                list[ResultatAnalyse]: liste des résultats d'analyse pour chaque fichier
        """
        try:
            resultats = []
            for fichier_chiffre in os.listdir(dossier_chiffres):
                chemin_fichier_chiffre = os.path.join(dossier_chiffres, fichier_chiffre)
                resultat = self.Analyser_fichier_uniquement(chemin_fichier_chiffre)
                resultats.append(resultat)
            return resultats
        except Exception as e:
            print(f"Erreur lors de l'analyse des fichiers: {str(e)}")
            return []