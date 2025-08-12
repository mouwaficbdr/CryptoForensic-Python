#!/usr/bin/env python3
"""
Script pour exécuter tous les tests du projet
"""

import sys
import os
import subprocess

def run_test_file(test_file):
    """Exécute un fichier de test"""
    print(f"\nExécution de {test_file}")
    print("=" * 50)
    
    try:
        # Ajouter le répertoire racine au path
        sys.path.insert(0, os.path.dirname(__file__))
        
        # Exécuter le test
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=True, text=True, cwd=os.path.dirname(__file__))
        
        if result.returncode == 0:
            print("✅ Tests réussis")
            print(result.stdout)
        else:
            print("❌ Tests échoués")
            print(result.stdout)
            print(result.stderr)
            
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution: {e}")
        return False

def main():
    """Exécute tous les tests disponibles"""
    print("Lancement des tests du projet CryptoForensic")
    print("=" * 60)
    
    tests = [
        "tests/test_global.py",
        "tests/test_analyzers.py"
    ]
    
    success_count = 0
    total_count = len(tests)
    
    for test_file in tests:
        if os.path.exists(test_file):
            if run_test_file(test_file):
                success_count += 1
        else:
            print(f"⚠️  Fichier de test non trouvé: {test_file}")
    
    print(f"\nRésumé: {success_count}/{total_count} tests réussis")
    
    if success_count == total_count:
        print("Résultat:Tous les tests passent !")
    else:
        print("Résultat: Certains tests ont échoué")

if __name__ == "__main__":
    main()
