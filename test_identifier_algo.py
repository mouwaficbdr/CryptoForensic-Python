#!/usr/bin/env python3
"""
Script de test croisé pour les méthodes identifier_algo de tous les analyzers
sur tous les fichiers de mission.

Ce script teste chaque analyzer sur chaque fichier mission pour vérifier
que les heuristiques de détection fonctionnent correctement.
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.append('.')

def test_identifier_algo():
    """Test croisé de toutes les méthodes identifier_algo"""
    
    print("=" * 60)
    print("TEST CROISÉ DES MÉTHODES IDENTIFIER_ALGO")
    print("=" * 60)
    
    # Import des analyzers
    try:
        from src.analyzers.aes_cbc_analyzer import Aes_Cbc_Analyzer
        from src.analyzers.aes_gcm_analyzer import Aes_Gcm_Analyzer
        from src.analyzers.chacha20_analyzer import ChaCha20_Analyzer
        from src.analyzers.blowfish_analyzer import Blowfish_Analyzer
        from src.analyzers.fernet_analyzer import FernetAnalyzer
        print("✅ Tous les analyzers importés avec succès")
    except Exception as e:
        print(f"❌ Erreur d'import: {e}")
        return
    
    # Configuration des analyzers
    analyzers = {
        'AES-CBC': Aes_Cbc_Analyzer(),
        'AES-GCM': Aes_Gcm_Analyzer(),
        'ChaCha20': ChaCha20_Analyzer(),
        'Blowfish': Blowfish_Analyzer(),
        'Fernet': FernetAnalyzer()
    }
    
    # Configuration des missions avec leurs algorithmes attendus
    missions = {
        'mission1.enc': 'AES-CBC',
        'mission2.enc': 'ChaCha20',
        'mission3.enc': 'Blowfish',
        'mission4.enc': 'AES-GCM',
        'mission5.enc': 'Fernet'
    }
    
    # Vérification de l'existence des fichiers
    print("\n📁 Vérification des fichiers de mission:")
    for mission_file in missions.keys():
        file_path = Path(f'data/{mission_file}')
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"  ✅ {mission_file} ({size} bytes)")
        else:
            print(f"  ❌ {mission_file} - FICHIER MANQUANT")
            return
    
    print("\n" + "=" * 60)
    print("RÉSULTATS DES TESTS")
    print("=" * 60)
    
    # Matrice des résultats
    results = {}
    
    # Test de chaque analyzer sur chaque mission
    for mission_file, expected_algo in missions.items():
        print(f"\n🎯 {mission_file} (Attendu: {expected_algo})")
        print("-" * 50)
        
        results[mission_file] = {}
        
        for analyzer_name, analyzer in analyzers.items():
            try:
                score = analyzer.identifier_algo(f'data/{mission_file}')
                results[mission_file][analyzer_name] = score
                
                # Formatage avec indicateurs visuels
                if analyzer_name == expected_algo:
                    if score >= 0.8:
                        status = "🟢 EXCELLENT"
                    elif score >= 0.6:
                        status = "🟡 BON"
                    elif score >= 0.4:
                        status = "🟠 MOYEN"
                    else:
                        status = "🔴 FAIBLE"
                else:
                    if score <= 0.2:
                        status = "✅ Correct (faible)"
                    elif score <= 0.4:
                        status = "⚠️  Attention"
                    else:
                        status = "❌ FAUX POSITIF"
                
                print(f"  {analyzer_name:10}: {score:.3f} - {status}")
                
            except Exception as e:
                results[mission_file][analyzer_name] = None
                print(f"  {analyzer_name:10}: ERROR - {str(e)[:50]}...")
    
    # Résumé des performances
    print("\n" + "=" * 60)
    print("RÉSUMÉ DES PERFORMANCES")
    print("=" * 60)
    
    correct_detections = 0
    total_tests = 0
    
    for mission_file, expected_algo in missions.items():
        if mission_file in results and expected_algo in results[mission_file]:
            score = results[mission_file][expected_algo]
            if score is not None:
                total_tests += 1
                if score >= 0.6:  # Seuil de détection acceptable
                    correct_detections += 1
                    print(f"✅ {mission_file}: {expected_algo} détecté avec {score:.3f}")
                else:
                    print(f"❌ {mission_file}: {expected_algo} mal détecté ({score:.3f})")
            else:
                print(f"💥 {mission_file}: {expected_algo} - ERREUR")
    
    # Statistiques finales
    if total_tests > 0:
        success_rate = (correct_detections / total_tests) * 100
        print(f"\n📊 TAUX DE RÉUSSITE: {correct_detections}/{total_tests} ({success_rate:.1f}%)")
        
        if success_rate >= 80:
            print("🎉 EXCELLENT - Les heuristiques fonctionnent bien!")
        elif success_rate >= 60:
            print("👍 BON - Quelques améliorations possibles")
        else:
            print("⚠️  ATTENTION - Les heuristiques nécessitent des corrections")
    
    # Détection des faux positifs
    print(f"\n🔍 ANALYSE DES FAUX POSITIFS:")
    false_positives = []
    
    for mission_file, expected_algo in missions.items():
        if mission_file in results:
            for analyzer_name, score in results[mission_file].items():
                if analyzer_name != expected_algo and score is not None and score > 0.4:
                    false_positives.append((mission_file, analyzer_name, score))
    
    if false_positives:
        print("  ⚠️  Faux positifs détectés:")
        for mission, analyzer, score in false_positives:
            print(f"    - {mission}: {analyzer} = {score:.3f}")
    else:
        print("  ✅ Aucun faux positif significatif détecté")
    
    print("\n" + "=" * 60)
    print("TEST TERMINÉ")
    print("=" * 60)

if __name__ == "__main__":
    test_identifier_algo()