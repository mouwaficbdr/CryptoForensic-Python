#!/usr/bin/env python3
"""
Test de déchiffrement pour chaque mission avec l'analyzer correspondant.
- Utilise keys/wordlist.txt pour générer les clés candidates
- Tente le déchiffrement et valide le texte avec utils.verifier_texte_dechiffre
- Affiche un récapitulatif des succès/échecs
"""

import sys
from pathlib import Path
from typing import Dict, Tuple, Type

# Assurer l'import du projet
sys.path.append('.')

from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
from src.analyzers.fernet_analyzer import FernetAnalyzer
from src.utils import verifier_texte_dechiffre

# Mapping missions -> (fichier, analyzer class)
MISSIONS: Dict[str, Tuple[str, Type]] = {
    'AES-CBC': ('data/mission1.enc', Aes_Cbc_Analyzer),
    'ChaCha20': ('data/mission2.enc', ChaCha20_Analyzer),
    'Blowfish': ('data/mission3.enc', Blowfish_Analyzer),
    'AES-GCM': ('data/mission4.enc', Aes_Gcm_Analyzer),
    'Fernet': ('data/mission5.enc', FernetAnalyzer),
}

WORDLIST = 'keys/wordlist.txt'


def test_dechiffrement_missions() -> None:
    print('=' * 70)
    print('TEST DE DECHIFFREMENT PAR MISSION')
    print('=' * 70)

    global_success = 0
    total = 0

    # Vérification préliminaire
    if not Path(WORDLIST).exists():
        print(f"❌ Wordlist manquante: {WORDLIST}")
        return

    for algo, (mission_path, AnalyzerCls) in MISSIONS.items():
        total += 1
        print(f"\n🎯 Mission: {mission_path} | Analyzer attendu: {algo}")
        if not Path(mission_path).exists():
            print(f"  ❌ Fichier introuvable: {mission_path}")
            continue

        analyzer = AnalyzerCls()

        # Génération des clés
        try:
            cles = analyzer.generer_cles_candidates(WORDLIST)
            print(f"  🔑 Clés candidates générées: {len(cles)}")
        except Exception as e:
            print(f"  💥 Erreur génération clés: {e}")
            cles = []

        if not cles:
            print("  ⚠️  Aucune clé candidate (le test peut échouer)")

        # Essais de déchiffrement
        trouve = False
        meilleure_stat = 0.0
        meilleure_cle = None
        meilleur_texte = b''

        for idx, cle in enumerate(cles):
            try:
                res = analyzer.dechiffrer(mission_path, cle)
            except ValueError as ve:
                # clés de taille invalide pour l'algo
                continue
            except FileNotFoundError:
                print(f"  💥 Fichier introuvable pendant le test: {mission_path}")
                break
            except Exception:
                # Toute autre erreur: considérer comme tentative échouée
                continue

            if not res:
                continue

            try:
                texte = res.decode('utf-8', errors='ignore')
            except Exception:
                texte = ''

            stats = verifier_texte_dechiffre(texte)
            taux = float(stats.get('taux_succes', 0.0))
            if taux > meilleure_stat:
                meilleure_stat = taux
                meilleure_cle = cle
                meilleur_texte = res

            # Seuil de succès raisonnable
            if taux >= 60.0:
                trouve = True
                break

        if trouve:
            global_success += 1
            print(f"  ✅ Déchiffrement RÉUSSI | Taux succès: {meilleure_stat:.2f}%")
        else:
            # Note: AES-GCM n'a pas d'implémentation de déchiffrement -> probablement échec
            hint = ''
            if algo == 'AES-GCM':
                hint = " (implémentation dechiffrer() absente)"
            print(f"  ❌ Déchiffrement ÉCHEC{hint} | Meilleur taux: {meilleure_stat:.2f}%")

    print('\n' + '=' * 70)
    print(f"RÉSUMÉ: {global_success}/{total} missions déchiffrées")
    if global_success == total:
        print('🎉 Tous les déchiffrements ont réussi !')
    else:
        print('⚠️  Certains déchiffrements ont échoué. Voir détails ci-dessus.')


if __name__ == '__main__':
    test_dechiffrement_missions()
