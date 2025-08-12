import sys
import unittest
from pathlib import Path

# Autoriser les imports depuis src/
sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.detecteur_crypto import DetecteurCryptoOrchestrateur


class IntegrationLegereTests(unittest.TestCase):
    """
    Tests d'intégration légers pour vérifier que le flux principal fonctionne
    sur les missions fournies, sans exiger de déchiffrement effectif.
    """

    def setUp(self) -> None:
        self.orchestrateur = DetecteurCryptoOrchestrateur()
        self.dossier_data = Path("data")
        self.wordlist = "keys/wordlist.txt"

    def test_analyse_scores_sans_crash(self):
        """
        Vérifie que l'appel d'analyse sur les fichiers .enc existants ne plante pas
        et produit au moins un score par fichier.
        """
        if not self.dossier_data.exists():
            self.skipTest("Dossier data/ introuvable.")

        fichiers = sorted([p for p in self.dossier_data.glob("*.enc")])
        if not fichiers:
            self.skipTest("Aucun fichier .enc dans data/ pour le test d'intégration.")

        # Pour chaque fichier, on appelle uniquement l'identification via l'orchestrateur.
        for f in fichiers:
            res = self.orchestrateur.analyser_fichier_specifique(
                f.name, progress=None, task=None, error=False, nbr_opr_mission=4
            )
            # Le score doit être un float borné [0,1]
            self.assertIsInstance(res.score_probabilite, float)
            self.assertGreaterEqual(res.score_probabilite, 0.0)
            self.assertLessEqual(res.score_probabilite, 1.0)

    def test_mission_complete_appel(self):
        """
        Vérifie que `mission_complete_automatique` s'exécute sans erreur et
        retourne une liste (même vide si data/ ne contient rien).
        """
        if not self.dossier_data.exists():
            self.skipTest("Dossier data/ introuvable.")

        resultats = self.orchestrateur.mission_complete_automatique(str(self.dossier_data), self.wordlist)
        self.assertIsInstance(resultats, list)


if __name__ == "__main__":
    unittest.main()

