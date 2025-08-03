from abc import ABC, abstractmethod

class CryptoAnalyzer(ABC):
    @abstractmethod
    def identifier_algo(self, chemin_fichier_chiffre: str) -> float:
        pass
    
    @abstractmethod
    def dechiffrer(self, chemin_fichier_chiffre: str, cle_donnee: bytes) -> bytes:
        pass
    
    @abstractmethod
    def generer_cles_candidates(self, chemin_dictionnaire: str) -> 'list[bytes]': 
        pass