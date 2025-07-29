# 🕵️‍♀️ CryptoForensic : Détecteur et Analyseur de Chiffrement Avancé

-----

## 🚀 Vue d'Ensemble du Projet

L'objectif principal de ce projet est d'agir comme un **"Détective Cryptographique"** en identifiant de manière autonome des algorithmes de chiffrement symétrique et en déchiffrant des communications interceptées. Ce projet met en œuvre des techniques de **cryptanalyse**, des **heuristiques d'identification** sophistiquées et une **architecture logicielle robuste** pour résoudre des missions de déchiffrement complexes.

Conçu avec une approche modulaire et évolutive, CryptoForensic vise à démontrer une maîtrise approfondie des principes de la cryptographie appliquée, de l'analyse forensique et de la programmation défensive.

-----

## ✨ Fonctionnalités Clés

  * **Identification Automatique d'Algorithmes :** Détection intelligente de l'algorithme de chiffrement (AES-256-CBC, ChaCha20, Blowfish, AES-256-GCM, Fernet) grâce à des heuristiques basées sur la structure des données, l'entropie et les signatures spécifiques.
  * **Capacités de Déchiffrement :** Implémentation fonctionnelle des 5 algorithmes de chiffrement mentionnés, avec gestion des clés, des IV/nonces et des tags d'authentification.
  * **Attaques par Dictionnaire Optimisées :** Module d'attaque par dictionnaire avec des optimisations de performance (parallélisation, cache) pour la découverte rapide de clés.
  * **Interface Console Interactive :** Une interface utilisateur en ligne de commande intuitive et colorée permettant l'analyse de fichiers, le suivi de progression et la génération de rapports détaillés.
  * **Programmation Défensive & Robuste :** Intégration de la gestion d'erreurs, de la validation des entrées et de bonnes pratiques de sécurité (pas de clés en dur, nettoyage mémoire).
  * **Suite de Tests Complète :** Couverture de code élevée (cible \>90%) avec des tests unitaires et d'intégration pour garantir la fiabilité et la robustesse du système.

-----

## 🛠️ Architecture & Technologies

Le projet est structuré autour d'une architecture modulaire, respectant les principes de conception logicielle et les patterns établis.

  * **Langage :** Python 3.x
  * **Bibliothèques Clés :**
      * `cryptography` : Pour des implémentations cryptographiques modernes et sécurisées.
      * `pycryptodome` : En complément pour certains algorithmes spécifiques.
      * `hashlib` : Pour la dérivation de clés.
      * `base64` : Pour les encodages de données.
  * **Conception :** Utilisation d'une **interface abstraite `CryptoAnalyzer`** pour définir un contrat clair pour chaque algorithme, orchestrée par la classe principale **`DetecteurCrypto`**.

-----

## 🚀 Installation

Suivez ces étapes pour configurer votre environnement de développement.

### 1. Clônage du Dépôt

```bash
git clone https://github.com/mouwaficbdr/CryptoForensic-Python.git
cd CryptoForensic-Python
```

### 2. Création et Activation de l'Environnement Virtuel

Il est recommandé d'utiliser un environnement virtuel pour isoler les dépendances du projet.

* **Sur Linux/macOS :**

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

* **Sur Windows :**

  ```bash
  python -m venv .venv
  .venv\Scripts\activate
  ```

### 3. Installation des Dépendances

Une fois l'environnement virtuel activé, installez les bibliothèques nécessaires à l'aide du fichier `requirements.txt` :

```bash
pip install -r requirements.txt
```

-----

## 📂 Arborescence du Projet

```
/home/mouwaficbdr/Bureau/CryptoForensic-Python/
├───main.py                             # Point d'entrée avec interface CLI
├───README.md
├───data/                               # Fichiers chiffrés pour les tests
├───docs/                               # Documentation du projet
├───keys/                               # Dictionnaires de mots de passe
├───src/                                # Code source de l'application
│   ├───crypto_analyzer.py              # Interface pour les analyseurs
│   ├───detecteur_crypto.py             # Moteur de détection
│   ├───interface_console.py            # Interface en ligne de commande
│   ├───rapport_mission.py              # Générateur de rapports
│   ├───utils.py                        # Fonctions utilitaires
│   └───analyzers/                      # Modules d'analyse par algorithme
│       ├───aes_cbc_analyzer.py
│       ├───aes_gcm_analyzer.py
│       ├───blowfish_analyzer.py
│       ├───chacha20_analyzer.py
│       └───fernet_analyzer.py
└───tests/                              # Scripts de test
    ├───test_analyzers.py
    ├───test_detecteur.py
    └───test_integration.py
```

## 🤝 Contributeurs

* [**AIHOUNHIN Eunock**](https://github.com/Eunock-web)
* [**ATOHOUN Andy**](https://github.com/e-mandy)
* [**BADAROU Mouwafic**](https://github.com/mouwaficbdr)
* [**OGOUDEDJI Seathiel**](https://github.com/seathiel-12)
* [**OKWUDIAFOR Wesley**](https://github.com/wesley-kami)

## 💡 Contribution

Ce projet est ouvert aux contributions. Pour toute idée d'amélioration, rapport de bug ou optimisation, veuillez ouvrir une *issue* ou soumettre une *pull request*.

