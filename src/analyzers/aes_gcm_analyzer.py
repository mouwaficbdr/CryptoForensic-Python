from src.crypto_analyzer import CryptoAnalyzer
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import List
import re

class Aes_Gcm_Analyzer(CryptoAnalyzer):
    '''Détermine si l'algo aes_gcm est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
    
        Cette classe a trois méthodes principales:
        - identifier_algo: Détermine si l'algo de chiffrement utilsé sur le fichier chiffré qui lui est passé en paramètre est l'aes_gcm.
        - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
        - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
        
        Attributes:
        _PBKDF2_SALT: le salt utilisé pour le chiffrement
        _PBKDF2_ITERATIONS: le nombre d'itérations faites au chiffrement
        _PBKDF2_LONGUEUR_CLE: la longueur en octets de la clé à utiliser
    '''
    
    _PBKDF2_SALT: bytes = b"AES_GCM_SALT_2024"  #Fourni
    _PBKDF2_ITERATIONS: int = 10000             #Fourni
    _PBKDF2_LONGUEUR_CLE: int = 32              #Longueur de la clé
    
    def __filtrer_dictionnaire_par_indices(self, chemin_dictionnaire: str) -> List[str]:
        """
        Filtre le dictionnaire en se basant sur les indices de la mission 4.
        L'indice pointe vers le format de clé "Acronyme en majuscules + 4 chiffres".
        """
        mots_filtres: List[str] = []
        annee_courante: str = "2024"  # Normalement 2025 mais on considère 2024 pour se conformer à la wordlist
        motif_acronyme = re.compile(r"^[A-Z]{4}$")

        try:
            with open(chemin_dictionnaire, "r", encoding="utf-8") as f:
                for ligne in f:
                    mot: str = ligne.strip()
                    if mot.endswith(annee_courante):
                        acronyme: str = mot[:-4]
                        if motif_acronyme.match(acronyme):
                            mots_filtres.append(mot)
        except FileNotFoundError:
            print(f"Erreur : Le fichier de dictionnaire '{chemin_dictionnaire}' est introuvable.")
            return []

        return mots_filtres

    def generer_cles_candidates(self, chemin_dictionnaire: str) -> List[bytes]:
        '''
        Génère les clées candidates pour déchiffrer le fichier à partir de la liste retournée par filtrer_dictionnaire_par_indices.
        
        Args:
            chemin_dictionnaire(str): le chemin du dictionnaire de mots de passes pour l'attaque par dictionnaire.
            
        Returns:
            list[bytes]: liste des clés candidates. 
        '''
        
        mots_de_passe_cible: List[str] = self.__filtrer_dictionnaire_par_indices(chemin_dictionnaire)
        
        clees_candidates: List[bytes] = []
        
        for mot_de_passe in mots_de_passe_cible:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self._PBKDF2_LONGUEUR_CLE,
                iterations=self._PBKDF2_ITERATIONS,
                salt=self._PBKDF2_SALT
            )
            mot_de_passe_en_octets: bytes = mot_de_passe.encode('utf-8')
            cle_derivee: bytes = kdf.derive(mot_de_passe_en_octets)
            clees_candidates.append(cle_derivee)

        return clees_candidates

    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        """
        Estime la probabilité que le fichier soit chiffré en AES-GCM.
        
        Idée générale:
        - Motif structurel attendu: nonce (12 octets) en tête, corps de données chiffrées, puis tag (16 octets) en fin.
        - Pas de padding bloc: la taille du corps n'est pas forcément multiple de 16.
        - Les vérifications structurelles ont un poids fort. L'entropie apporte seulement des signaux faibles.
        
        Args:
            chemin_fichier_chiffre(str): Le chemin vers le fichier chiffré.
            
        Returns:
            float: Probabilité que le fichier utilise AES GCM (0.0 à 1.0).
        """
        try:
            with open(chemin_fichier_chiffre, "rb") as f:
                contenu_fichier: bytes = f.read()

            # Garde 1: taille minimale (nonce 12 + tag 16 + au moins 1 octet de corps)
            if len(contenu_fichier) < 12 + 1 + 16:
                return 0.0

            # Placement attendu: [0:12] = nonce, [-16:] = tag, [12:-16] = corps
            nonce: bytes = contenu_fichier[:12]
            tag: bytes = contenu_fichier[-16:]
            corps: bytes = contenu_fichier[12:-16]

            # Garde 2: tailles strictes
            if len(nonce) != 12 or len(tag) != 16 or len(corps) <= 0:
                return 0.0

            from src.utils import calculer_entropie
            score: float = 0.0

            # Signal positif fort (structure GCM): corps non multiple de 16 → pas de padding bloc
            if len(corps) % 16 != 0:
                score += 0.50
            else:
                # Signal négatif (mode bloc typique) : pénalité renforcée
                score -= 0.50

            # Taille totale multiple de 16 : peu probable pour GCM (plus proche AES/Blowfish)
            if len(contenu_fichier) % 16 == 0:
                score -= 0.40

            # Autres signaux négatifs "mode bloc":
            # - IV 16B plausible en tête + corps multiple de 16 (plutôt AES-CBC)
            if len(contenu_fichier) >= 16:
                iv16 = contenu_fichier[:16]
                corps16 = contenu_fichier[16:]
                try:
                    if len(corps16) > 0 and (len(corps16) % 16) == 0 and calculer_entropie(iv16) > 7.0:
                        score -= 0.30
                except Exception:
                    pass
            # - IV 8B plausible en tête + corps multiple de 8 (plutôt Blowfish)
            if len(contenu_fichier) >= 8:
                iv8 = contenu_fichier[:8]
                corps8 = contenu_fichier[8:]
                if len(corps8) > 0 and (len(corps8) % 8) == 0:
                    score -= 0.25

            # Si les 16 derniers octets ne ressemblent PAS à un tag AEAD (faible entropie), on pénalise.
            queue16 = contenu_fichier[-16:] if len(contenu_fichier) >= 16 else b""
            try:
                if queue16 and calculer_entropie(queue16) <= 7.0:
                    score -= 0.30
            except Exception:
                pass

            # Entropie: signaux faibles (ne doivent jamais suffire à rendre positif tout seuls)
            ent_tag = calculer_entropie(tag)
            if ent_tag > 7.2:
                score += 0.10
            if len(corps) > 0 and calculer_entropie(corps) > 7.0:
                score += 0.10
            # Nonce aléatoire plausible (faible poids)
            try:
                ent_nonce = calculer_entropie(nonce)
                if ent_nonce > 7.0:
                    score += 0.08
                else:
                    # Nonce peu aléatoire: contre-signal pour GCM
                    score -= 0.10
            except Exception:
                pass

            # Cas ambigu : nonce/tag semblent aléatoires mais le corps est aligné sur 16 octets → pénalité supplémentaire
            try:
                if (ent_nonce if 'ent_nonce' in locals() else 0) > 7.0 and ent_tag > 7.2 and (len(corps) % 16) == 0:
                    score -= 0.10
            except Exception:
                pass

            # Normalisation, on borne toujours le score dans [0, 1]
            if score < 0.0:
                score = 0.0
            if score > 1.0:
                score = 1.0
            return score
            
        except FileNotFoundError:
            print(f"Erreur : Le fichier '{chemin_fichier_chiffre}' est introuvable.")
            return 0.0
        except Exception as e:
            print(f"Erreur lors de l'identification de l'algorithme AES GCM: {e}")
            return 0.0  

    def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
        """
        Déchiffre le fichier chiffré avec la clé donnée.
        
        Args:
            chemin_fichier_chiffre(str): Le chemin vers le fichier chiffré.
            cle_donnee(bytes): La clé de déchiffrement.
            
        Returns:
            bytes: Le contenu déchiffré ou une chaîne vide en cas d'échec.
        """
        try:
            # Validation taille de clé: AES-256 => 32 octets
            if len(cle_donnee) != self._PBKDF2_LONGUEUR_CLE:
                raise ValueError("Erreur : La clé AES-256 doit faire 32 bytes")

            # Lecture du fichier: nonce (12B) + données + tag (16B)
            with open(chemin_fichier_chiffre, "rb") as f:
                donnees = f.read()

            if len(donnees) < 12 + 16:
                return b""

            nonce = donnees[:12]
            ciphertext_tag = donnees[12:]
            if len(ciphertext_tag) < 16:
                return b""
            ciphertext = ciphertext_tag[:-16]
            tag = ciphertext_tag[-16:]

            # Déchiffrement AES-GCM
            cipher = Cipher(algorithms.AES(cle_donnee), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return plaintext
            except Exception:
                # Tag invalide / clé incorrecte
                return b""

        except FileNotFoundError:
            raise
        except ValueError as e:
            # Erreur de validation de clé
            if "doit faire 32 bytes" in str(e):
                raise
            return b""
        except Exception as e:
            # Erreur générique
            return b""