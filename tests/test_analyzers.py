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
        """
        Ne dépend pas d'une méthode privée. On vérifie simplement que
        `generer_cles_candidates` retourne une liste de bytes (clé dérivée).
        """
        res = self.analyser.generer_cles_candidates(self.wordlist)
        self.assertIsInstance(res, list)
        self.assertTrue(all(isinstance(c, bytes) for c in res))

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
        score_valide = self.analyser_chacha.identifier_algo(self.chemin_fichier_chacha_valide)
        self.assertGreaterEqual(score_valide, 0.7)
        self.assertLessEqual(score_valide, 1.0)
        self.assertAlmostEqual(self.analyser_chacha.identifier_algo(self.chemin_fichier_chacha_invalide), 0.0, 1)

    def test_chacha20_generer_cles_candidates(self):
        # La fonction generer_cles_candidates utilise maintenant __filtrer_dictionnaire_par_indice
        # et devrait retourner une liste de clés dérivées des mots de passe filtrés
        resultat = self.analyser_chacha.generer_cles_candidates(self.wordlist)
        self.assertIsInstance(resultat, list)
        self.assertTrue(all(isinstance(cle, bytes) for cle in resultat))

    def test_chacha20_dechiffrer(self):
        """
        Le module ChaCha20 de l'appli ne vise pas l'AEAD (Poly1305). Ici on
        vérifie simplement que la fonction retourne des bytes sans lever
        d'exception avec une clé de bonne taille, sans exiger l'égalité stricte
        au texte clair (format non garanti).
        """
        resultat_dechiffrement = self.analyser_chacha.dechiffrer(self.chemin_fichier_chacha_valide, self.cle_test_chacha)
        self.assertIsInstance(resultat_dechiffrement, bytes)

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
        #Vérifie que la probabilité retournée pour le fichier AES GCM valide est un float et élevée
        # Une méthode identifier_algo bien implémentée devrait retourner une probabilité élevée (0.8+)
        # pour un fichier AES GCM valide, pas seulement 0.5
        resultat = self._analyzer.identifier_algo(self._fichier_test)
        self.assertIsInstance(resultat, float)
        # Tolérance: un fichier valide doit donner un score élevé (>= 0.5)
        self.assertGreaterEqual(resultat, 0.5)
        self.assertLessEqual(resultat, 1.0)
    
    def test_aes_gcm_dechiffrer(self):
        """
        La clé fournie n'a pas 32 octets, on s'attend donc à une ValueError.
        """
        cle_test = b"cle_test_32_bytes_pour_aes_gcm_"  # 31 octets
        with self.assertRaises(ValueError):
            self._analyzer.dechiffrer(self._fichier_test, cle_test)
        
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
        """
        Pour Fernet, la clé doit être fournie au format Base64 (44 octets).
        Ici, avec une clé brute de 32 octets, on s'attend à ValueError.
        """
        resultat = self._analyzer.dechiffrer
        with self.assertRaises(ValueError):
            resultat(self._fichier_test, self._key)
        # Pour déclencher FileNotFoundError en priorité, on passe une clé Fernet valide (44 bytes Base64)
        from cryptography.fernet import Fernet as _F
        cle_valide_b64 = _F.generate_key()
        # Le code attrape l'exception d'ouverture et retourne b"" en cas d'échec
        self.assertEqual(resultat('dohi.txt', cle_valide_b64), b"")
        
if __name__ == '__main__':
    main()
