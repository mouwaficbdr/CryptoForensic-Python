from abc import ABC
class Crypto_analyzers(ABC):
    @abs
    def identifier_algo(self, fichier):
        pass
    
    @abs
    def dechiffrer(self, fichier, cle):
        pass
    
    @abs
    def generer_cles_candidates(self, algo):
        pass
        