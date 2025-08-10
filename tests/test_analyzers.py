from unittest import TestCase, main
import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer


class AesCbcAnalyzerTester(TestCase):
    """
    Cette classe est principalement destinée à recueillir toutes les fonctions de test des analyseurs d'algorithme
    de chiffrement.
    """
    
    def setUp(self):
        self.chemin_fichier_chiffre = "data/mission1.enc"
        self.chemin_fichier_chiffre_invalide = "tests/fichiers_pour_tests/mission1_invalide.enc"
        self.wordlist = "keys/wordlist.txt"
        self.analyser = Aes_Cbc_Analyzer()

    
    def test_aes_cbc_identifier_algo(self):
        self.assertAlmostEqual(self.analyser.identifier_algo(self.chemin_fichier_chiffre), 1.0, delta=0.1)
        self.assertAlmostEqual(self.analyser.identifier_algo(self.chemin_fichier_chiffre_invalide), 0)

    def test_aes_cbc_filtrage_dict(self):
        self.assertIsInstance(self.analyser.filtrer_dictionnaire_par_indices(self.wordlist), list)
        self.assertEqual(self.analyser.filtrer_dictionnaire_par_indices(self.wordlist), ["paris2024"])
        self.assertEqual(self.analyser.filtrer_dictionnaire_par_indices("chemin_dohi.txt"), [])

    def test_generation_cles_candidate(self):
        self.assertIsInstance(self.analyser.generer_cles_candidates(self.wordlist), list)

    def test_exception_dechiffrer(self):
        cles_candidates = self.analyser.generer_cles_candidates(self.wordlist)
        
        if not cles_candidates:
            self.fail("La liste des clés candidates ne devrait pas être vide.")
        
        premiere_cle = cles_candidates[0]
        
        with self.assertRaises(FileNotFoundError):
            self.analyser.dechiffrer("no_file_dohi.txt", premiere_cle)
            
class ChaCha20AnalyzerTester(TestCase):

    def setUp(self):
        # Chemins pour ChaCha20_Analyzer
        self.wordlist = "keys/wordlist.txt"
        self.analyser_chacha = ChaCha20_Analyzer()

        # Données de test pour ChaCha20
        self.cle_test_chacha = hashlib.sha256(b"cle_test").digest()
        self.nonce_test_chacha = b"\x00" * 12
        self.texte_clair_test_chacha = b"Bonjour le monde, ceci est un test de chiffrement ChaCha20"
        self.chemin_fichier_chacha_valide = "tests/fichiers_pour_tests/mission_chacha20_temp.enc"
        self.chemin_fichier_chacha_invalide = "tests/fichiers_pour_tests/chacha20_invalide.enc"

        # Générer un fichier chiffré valide pour les tests de ChaCha20
        aead = ChaCha20Poly1305(self.cle_test_chacha)
        texte_chiffre_test = aead.encrypt(self.nonce_test_chacha, self.texte_clair_test_chacha, None)
        with open(self.chemin_fichier_chacha_valide, "wb") as f:
            f.write(self.nonce_test_chacha)
            f.write(texte_chiffre_test)

    def tearDown(self):
        if os.path.exists(self.chemin_fichier_chacha_valide):
            os.remove(self.chemin_fichier_chacha_valide)
            
    # Ajout des tests pour ChaCha20_Analyzer
    def test_chacha20_identifier_algo(self):
        self.assertAlmostEqual(self.analyser_chacha.identifier_algo(self.chemin_fichier_chacha_valide), 0.8, 1)
        self.assertAlmostEqual(self.analyser_chacha.identifier_algo(self.chemin_fichier_chacha_invalide), 0.0, 1)

    def test_chacha20_generer_cles_candidates(self):
        # Comme la fonction filtrer_dictionnaire_par_indices retourne toujours une liste vide,
        # generer_cles_candidates doit également retourner une liste vide.
        self.assertEqual(self.analyser_chacha.generer_cles_candidates(self.wordlist), [])

    def test_chacha20_dechiffrer(self):
        # Test de déchiffrement avec une clé et un nonce valides
        resultat_dechiffrement = self.analyser_chacha.dechiffrer(self.chemin_fichier_chacha_valide, self.cle_test_chacha)
        self.assertEqual(resultat_dechiffrement, self.texte_clair_test_chacha)

        # Test de déchiffrement avec une clé incorrecte
        cle_incorrecte = hashlib.sha256(b"mauvaise_cle").digest()
        resultat_incorrect = self.analyser_chacha.dechiffrer(self.chemin_fichier_chacha_valide, cle_incorrecte)
        self.assertNotEqual(resultat_incorrect, self.texte_clair_test_chacha)

    def test_chacha20_dechiffrer_mauvaise_cle(self):
        # Test de l'exception pour une clé de taille incorrecte
        cle_mauvaise_taille = b"a" * 16 # La bonne taille est 32
        with self.assertRaises(ValueError):
            self.analyser_chacha.dechiffrer(self.chemin_fichier_chacha_valide, cle_mauvaise_taille)

    def test_chacha20_dechiffrer_fichier_non_existant(self):
        # Test de l'exception si le fichier n'existe pas
        cle_valide = self.cle_test_chacha
        with self.assertRaises(FileNotFoundError):
            self.analyser_chacha.dechiffrer("chemin_invalide.enc", cle_valide)
            
class AesGcmTester(TestCase) :
    _wordlist = "keys/wordlist.txt"
    _analyzer=Aes_Gcm_Analyzer()
    _fichier="data/mission3.enc"
    _fichier_test = Path('tests/fichiers_pour_tests') / 'aes_gcm_invalide.enc'
    _texte_test = b"Test effectue pour AesGcm, encore. Nous en sommes a la.fin"
    
    
    def setUp(self): 
        """
        Crée un fchier de test crypté en AESGCM pour les tests unitaires
        """
        key = AESGCM.generate_key(128)
        nonce = os.urandom(12)
        aad = os.urandom(16)
        texte_chiffre = AESGCM(key).encrypt(nonce, self._texte_test, aad)
        with open(self._fichier_test, '+wb') as f:
            f.write(nonce)
            f.write(texte_chiffre)
        f.close()
        
    def test_aesgcm_generer_cles_candidates(self):
        #Vérifie que les clés candidates générés par cet algorithme sont une liste de bytes
        with self.assertRaises(ValueError):
            self.assertIsInstance(self._analyzer.generer_cles_candidates(self._wordlist), list[bytes])
    
    def test_aes_gcm_identifier_algo(self):
        #Vérifie que la probabilité retournée pour le fichier mission3.enc est un float et élevée
        with self.assertRaises(ValueError):
            self.assertIsInstance(self._analyzer.identifier_algo(self._fichier_test), float)
        self.assertAlmostEqual(self._analyzer.identifier_algo(self._fichier_test, 0))
    
    def test_aes_gcm_dechiffrer(self):
        self.assertIsInstance(self._analyzer.dechiffrer(self._fichier_test), bytes)
        
      

if __name__ == '__main__':
    main()