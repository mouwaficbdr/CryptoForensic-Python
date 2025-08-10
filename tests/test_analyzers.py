import base64
from unittest import TestCase, main
import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
from src.analyzers.fernet_analyzer import FernetAnalyzer



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
        resultat = self._analyzer.generer_cles_candidates(self._wordlist)
        self.assertIsInstance(resultat, list)
        # Vérifier que tous les éléments sont des bytes
        for cle in resultat:
            self.assertIsInstance(cle, bytes)
    
    def test_aes_gcm_identifier_algo(self):
        #Vérifie que la probabilité retournée pour le fichier mission3.enc est un float et élevée
        resultat = self._analyzer.identifier_algo(self._fichier_test)
        self.assertIsInstance(resultat, float)
        self.assertAlmostEqual(resultat, 0.5, places=1)
    
    def test_aes_gcm_dechiffrer(self):
        # Créer une clé de test pour le déchiffrement
        cle_test = b"cle_test_32_bytes_pour_aes_gcm_"
        resultat = self._analyzer.dechiffrer(self._fichier_test, cle_test)
        self.assertIsInstance(resultat, bytes)
        
class FernetTester(TestCase) :
    _wordlist = "keys/wordlist.txt"
    _analyzer=FernetAnalyzer()
    _fichier_test = Path('tests/fichiers_pour_tests') / 'fernet_invalide.enc'
    _texte_test = b"Test effectue pour Fernet, encore. Nous en sommes a la.fin"   
    _key = os.urandom(32)

    def setUp(self):
        """
        Crée un fichier pour les tests relatifs à Fernet
        """
        try :
            with open(self._fichier_test, 'wb') as f:
                texte_chiffre = Fernet(base64.urlsafe_b64encode(self._key)).encrypt(self._texte_test)
                f.write(texte_chiffre)
            f.close()
        except FileNotFoundError :
            raise
        
    def test_fernet_gk(self):
        resultat = self._analyzer.generer_cles_candidates(self._wordlist)
        self.assertIsInstance(resultat, list)
        # Vérifier que tous les éléments sont des bytes
        for cle in resultat:
            self.assertIsInstance(cle, bytes)
            
    def test_fernet_id_algo(self):
        #Vérifier que seul le fichier mission 5 a plus de 0.8 de score pour l'identification de Fernet
        for i in range(5) :
            if i+1 != 5 and self._analyzer.identifier_algo(f"mission{i+1}.enc") >= 0.8:
                raise Exception('Non correspondance entre probabilité et algorithme.')  
    
    def test_dechiffrer(self) :
        #Vérifie que le déchiffrement de fernet est opérationnel
        resultat = self._analyzer.dechiffrer
        self.assertEqual(resultat(self._fichier_test, self._key), self._texte_test)
        
        #Vérifie le cas de clé non correspondante
        with self.assertRaises(ValueError) :
            self.assertIsInstance(resultat(self._fichier_test, os.urandom(16)), ValueError)
        
        #Vérifie le cas de fichier non trouvé
        with self.assertRaises(FileNotFoundError):
            self.assertIsInstance(resultat('dohi.txt', os.urandom(32)), FileNotFoundError)     
        
if __name__ == '__main__':
    main()
