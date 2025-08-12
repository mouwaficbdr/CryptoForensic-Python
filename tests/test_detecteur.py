import sys
import time
import unittest
from pathlib import Path

# Autoriser les imports depuis src/
sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.detecteur_crypto import DetecteurCryptoOrchestrateur, ResultatAnalyse


class FakeProgress:
    """
    Progress factice pour les tests.
    Fournit les mêmes méthodes que rich.Progress utilisées dans le code,
    mais sans aucun effet de bord (pas d'affichage, pas de timing).
    """

    def add_task(self, description: str, total: int = 100):
        return 1  # identifiant quelconque

    def update(self, task_id=None, description: str = "", advance: float = 0.0):
        pass

    def remove_task(self, task_id):
        pass


class DetecteurCryptoTests(unittest.TestCase):
    """
    Tests unitaires pour l'orchestrateur: vérifie les retours et la robustesse
    des appels les plus utilisés, sans dépendre de l'affichage.
    """

    def setUp(self) -> None:
        self.orchestrateur = DetecteurCryptoOrchestrateur()
        self.progress = FakeProgress()
        self.wordlist = "keys/wordlist.txt"

    def test_analyser_fichier_specifique_type(self):
        """
        Vérifie que l'analyse d'un fichier retourne un ResultatAnalyse
        et ne lève pas d'exception avec une Progress factice.
        """
        resultat = self.orchestrateur.analyser_fichier_specifique(
            "mission1.enc", progress=self.progress, task=self.progress.add_task("t"), error=False, nbr_opr_mission=4
        )
        self.assertIsInstance(resultat, ResultatAnalyse)
        self.assertIsInstance(resultat.score_probabilite, float)
        self.assertIsInstance(resultat.nb_tentatives, int)

    def test_mission_complete_automatique_sans_exception(self):
        """
        Vérifie qu'une mission complète ne plante pas et retourne une liste
        de ResultatAnalyse. Le contenu exact dépend de data/.
        """
        dossier_data = Path("data")
        if not dossier_data.exists():
            self.skipTest("Dossier data/ introuvable pour le test d'intégration léger.")

        resultats = self.orchestrateur.mission_complete_automatique(str(dossier_data), self.wordlist)

        self.assertIsInstance(resultats, list)
        for r in resultats:
            self.assertIsInstance(r, ResultatAnalyse)
            self.assertIsInstance(r.algo, str)
            self.assertIsInstance(r.score_probabilite, float)

        # On n'impose pas de borne de durée pour éviter un test fragile.


if __name__ == "__main__":
    unittest.main()

