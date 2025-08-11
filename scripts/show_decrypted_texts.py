#!/usr/bin/env python3
"""
Affiche les textes déchiffrés pour chaque mission en utilisant l'analyzer correspondant.
"""
import sys
from pathlib import Path
from typing import Dict, Tuple, Type

sys.path.append('.')

from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
from src.analyzers.fernet_analyzer import FernetAnalyzer
from src.utils import verifier_texte_dechiffre

MISSIONS: Dict[str, Tuple[str, Type]] = {
    'AES-CBC': ('data/mission1.enc', Aes_Cbc_Analyzer),
    'ChaCha20': ('data/mission2.enc', ChaCha20_Analyzer),
    'Blowfish': ('data/mission3.enc', Blowfish_Analyzer),
    'AES-GCM': ('data/mission4.enc', Aes_Gcm_Analyzer),
    'Fernet': ('data/mission5.enc', FernetAnalyzer),
}

WORDLIST = 'keys/wordlist.txt'


def main() -> None:
    if not Path(WORDLIST).exists():
        print(f"Wordlist manquante: {WORDLIST}")
        sys.exit(1)

    for algo, (mission_path, AnalyzerCls) in MISSIONS.items():
        print("=" * 70)
        print(f"{algo} -> {mission_path}")
        if not Path(mission_path).exists():
            print(f"Fichier introuvable: {mission_path}")
            continue

        analyzer = AnalyzerCls()
        try:
            cles = analyzer.generer_cles_candidates(WORDLIST)
        except Exception as e:
            print(f"Erreur génération clés: {e}")
            cles = []

        meilleure_stat = -1.0
        meilleur_texte_b = b''
        meilleure_cle = None

        for cle in cles:
            try:
                res = analyzer.dechiffrer(mission_path, cle)
            except Exception:
                continue
            if not res:
                continue
            # Sanitize and score
            texte = res.decode('utf-8', errors='ignore').replace('\x00', ' ')
            try:
                taux = float(verifier_texte_dechiffre(texte).get('taux_succes', 0.0))
            except Exception:
                taux = 0.0
            if taux > meilleure_stat:
                meilleure_stat = taux
                meilleur_texte_b = res
                meilleure_cle = cle
            # Early stop on good plaintext
            if taux >= 60.0:
                break

        if meilleure_cle is None:
            print("❌ Aucun texte déchiffré trouvé")
        else:
            texte = meilleur_texte_b.decode('utf-8', errors='ignore')
            print(f"✅ Meilleur taux: {meilleure_stat:.2f}%")
            print("--- TEXTE DÉCHIFFRÉ ---")
            print(texte.strip())
            print("------------------------")

if __name__ == '__main__':
    main()
