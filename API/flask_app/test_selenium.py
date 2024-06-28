
from selenium import webdriver
from selenium.webdriver.common.keys import Keys


# créer une instance du navigateur Chrome
driver = webdriver.Chrome()

# naviguer vers la page de connexion
driver.get("https://localhost:8800/token")

# trouver les champs de saisie pour le nom d'utilisateur et le mot de passe
username = driver.find_element_by_id("username")
password = driver.find_element_by_id("password")

# saisir les informations de connexion
username.send_keys("zgh")
password.send_keys("1234")

# soumettre le formulaire en cliquant sur le bouton de connexion
login_button = driver.find_element_by_id("se connecter")
login_button.click()

# vérifier si nous avons été redirigés vers la page d'accueil après la connexion réussie
assert "TABLEAU DE BORD" in driver.title


# fermer le navigateur
driver.close()