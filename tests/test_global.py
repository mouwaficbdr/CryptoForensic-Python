# import de la library pour les tests
from unittest import TestCase, main
import sys
sys.path.append('.')
sys.path.append('..')
from src.utils import verifier_texte_dechiffre, calculer_entropie
""" 
Ici le TestCase pour le regroupement des Cas de figures de Tests et le main pour l'exécution automatique des tests définis dans la classe ci-dessous

"""

# Définition d'une fonction d'addition (+) pour les tests 
def add(a,b):
    return a+b

class BetaTester(TestCase):
    #Définition de la méthode de test
    """ 
        # La fonction doit être préfixé du mot test pour que le TestCase puisse le l'identifier en tant que méthode à tester (le snake_case ici devra être appliqué ici) 

        # En fonction du type de vérification que vous souhaitez effectué par rapport aux test les méthodes assert devront variés.
        ex : * assertEqual() pour vérifier l'égalité. Dans le cas utilisé cette fonction vérifie si le retour de la fonction add correspond à la valeur 10
            * assertIn() pour vérifier si une variable est dans une iterable
            * assertIsInstance() pour vérifier le type de retour d'une variable ou fonction etc... (description des méthodes à l'appui)

        NB : Pour tester sa fonction chacun devra faire un import pour éviter la redondance.
        Chaque fonction à tester devra se retrouver dans la class BetaTester avec un nom clair et propre à sa fonctionnalité précédé du mot "test"

        command : pyhton test_global.py [-v (-- verbose)] (verbose pour un test avec plus de précision)

    """

    def test_addition(self):
        self.assertEqual(add(5,5),10)


    def test_verification_texte_dechiffre(self):
        resultat = verifier_texte_dechiffre("je talk !a mamamia:?")
        self.assertAlmostEqual(resultat['imprimable'], 100.0)
        self.assertEqual(resultat['nombre_mots'], 4)
        self.assertAlmostEqual(resultat['p_mots_valide'], 75.0)
        self.assertEqual(resultat['non_mots'], ["mamamia"])
        self.assertEqual(resultat['ponctuation_valide'], 1)

    def test_calcul_entropie(self) -> None:
        self.assertGreater(calculer_entropie("aaaaaaaa"), 0)


if __name__ == '__main__':
    main()