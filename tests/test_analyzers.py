from unittest import TestCase, main
import sys
sys.path.append('.')
sys.path.append('..')
from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer

class AnalyzersTester(TestCase):

    """
        Cette classe est principalement destinée à recueillir toutes les fonctions de test des analyseurs d'algorithme
        de chiffrement.
    """
    
    def setUp(self):
        self.chemin_fichier_chiffre = "data/mission1.enc"
        self.wordlist = "keys/wordlist.txt"
        self.analyser = Aes_Cbc_Analyzer()

    
    def test_aes_cbc_identifier_algo(self):
        self.assertAlmostEqual(self.analyser.identifier_algo(self.chemin_fichier_chiffre), 1)

    def test_aes_cbc_filtrage_dict(self):
        self.assertIsInstance(self.analyser.filtrer_dictionnaire_par_indices(self.wordlist), list)

    def test_generation_cles_candidate(self):
        self.assertIsInstance(self.analyser.generer_cles_candidates(self.wordlist), list)

    def test_exception_dechiffrer(self):
        cles_candidates = self.analyser.generer_cles_candidates(self.wordlist)
        
        if not cles_candidates:
            self.fail("La liste des clés candidates ne devrait pas être vide.")
        
        premiere_cle = cles_candidates[0]
        
        with self.assertRaises(FileNotFoundError):
            self.analyser.dechiffrer("no_file_dohi.txt", premiere_cle)

if __name__ == '__main__':
    main()