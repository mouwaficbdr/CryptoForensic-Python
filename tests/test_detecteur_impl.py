import os
import sys
import unittest
from pathlib import Path

# Permettre l'import du package src/
sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.detecteur_crypto import DetecteurCryptoOrchestrateur, ResultatAnalyse


class FakeProgress:
    """Progress factice (sans affichage) pour éviter les effets de bord."""

    def add_task(self, description: str, total: int = 100):
        return 1

    def update(self, task_id=None, description: str = "", advance: float = 0.0):
        pass

    def remove_task(self, task_id):
        pass


class DetecteurOrchestrateurTests(unittest.TestCase):
    """
    Tests ciblés sur l'orchestrateur `DetecteurCryptoOrchestrateur`.
    Objectif: vérifier que l'analyse d'un fichier spécifique fonctionne et
    que les structures de retour sont correctes.
    """

    def setUp(self) -> None:
        self.orchestrateur = DetecteurCryptoOrchestrateur()
        self.dossier_data = Path("data")
        # Fichier existant attendu dans le projet
        self.fichier_existant = "mission1.enc"
        # Dictionnaire standard
        self.wordlist = "keys/wordlist.txt"
        self.progress = FakeProgress()

    def test_analyser_fichier_specifique_retour_type(self):
        """
        Vérifie que l'appel à `analyser_fichier_specifique` retourne un objet `ResultatAnalyse`.
        On utilise une Progress factice (None) et des paramètres par défaut simples.
        """
        # Progress étant utilisé pour l'affichage, on passe None et on adapte les paramètres.
        # On s'assure simplement que l'appel ne lève pas d'exception et retourne le bon type.
        resultat = self.orchestrateur.analyser_fichier_specifique(
            self.fichier_existant, progress=self.progress, task=self.progress.add_task("t"), error=False, nbr_opr_mission=4
        )
        self.assertIsInstance(resultat, ResultatAnalyse)
        self.assertIsInstance(resultat.score_probabilite, float)
        self.assertIsInstance(resultat.nb_tentatives, int)

    def test_mission_complete_automatique_retour(self):
        """
        Vérifie que `mission_complete_automatique` retourne une liste de `ResultatAnalyse` et
        qu'elle ne plante pas lorsque le dossier `data/` contient les missions.
        """
        if not self.dossier_data.exists():
            self.skipTest("Dossier data/ introuvable dans l'environnement de test.")

        resultats = self.orchestrateur.mission_complete_automatique(str(self.dossier_data), self.wordlist)

        # Doit retourner une liste (potentiellement 0..N éléments selon le contenu de data/)
        self.assertIsInstance(resultats, list)
        for r in resultats:
            self.assertIsInstance(r, ResultatAnalyse)
            self.assertIsInstance(r.algo, str)
            self.assertIsInstance(r.score_probabilite, float)
            self.assertIsInstance(r.temps_execution, float)

        # Pas d'assertion de durée pour éviter la fragilité des tests.


if __name__ == "__main__":
    unittest.main()
