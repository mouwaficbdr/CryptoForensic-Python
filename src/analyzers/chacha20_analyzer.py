# Import des modules
from ..crypto_analyzer import CryptoAnalyzer

class ChaCha20_Analyzer(CryptoAnalyzer):
    """
    Détermine si l'algo ChaCha20 est utilisé, génère des clés et tente de de déchffrer un fichier chiffré en utilisant les clés générées.
    
    Cette classe a trois méthodes:
    - identifier_algo: Détermine si l'algo de chiffrement utilisé sur le fichier chiffré qui lui est passé en paramètre est l'ChaCha20.
    - generer_cles_candidates: Génère une liste de clés candidates pour le déchiffrement du fichier chiffré
    - dechiffrer: fait le déchiffrement proprement dit sur la base de la liste des clés générées
    
    Attributes:
    _CHACHA20_LONGUEUR_CLE: la taille de la clé de chiffrement (32 octets)
    _CHACHA20_LONGUEUR_NONCE: la taille du vecteur d'initialisation (12 octets)
    _CHACHA20_LONGUEUR_TAG: la taille de l'empreinte de chiffrement (16 octets)
    _CHACHA20_LONGUEUR_BLOC: la taille du bloc de chiffrement (64 bits)
    """

    _CHACHA20_LONGUEUR_CLE = 32
    _CHACHA20_LONGUEUR_NONCE = 12 #fourni
    _CHACHA20_LONGUEUR_TAG = 16
    _CHACHA20_LONGUEUR_BLOC = 64

    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        """
        Détermine la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 en:
        - vérifiant la taille du fichier chiffré
        - vérifiant la présence d'un tag de chiffrement
        - vérifiant la présence d'un vecteur d'initialisation
        - vérifiant la présence d'un bloc de chiffrement
        
        Retourne une probabilité entre 0 et 1(Pour connaitre la probabilité que l'algo de chiffrement utilisé soit l'ChaCha20).
        
        Args:
            chemin_fichier_chiffre(str): le chemin du fichier chiffré à traiter .
            
        Returns:
            float: La probabilité que l'algo de chiffrement utilisé soit l'ChaCha20 apres le calcul.
        """
        pass
        