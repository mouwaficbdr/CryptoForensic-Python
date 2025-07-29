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


## 🛣️ Perspectives Futures

Ce projet est une base solide pour explorer des fonctionnalités plus avancées, telles que la cryptanalyse fréquentielle, l'intégration d'algorithmes asymétriques, ou l'ajout de visualisations graphiques.

-----
