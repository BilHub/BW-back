from selenium import webdriver

# Ouvrir le navigateur
driver = webdriver.Chrome()

# Charger la page Web avec le formulaire
driver.get("http://localhost:8800/token")


# Remplir les champs de saisie du formulaire
username_input = driver.find_element_by_id("username")
password_input = driver.find_element_by_id("password")
username_input.send_keys("zgh")
password_input.send_keys("1234")

# Cliquer sur le bouton de connexion
login_button = driver.find_element_by_id("login-button")
login_button.click()

# Vérifier que la page de connexion a été remplacée par la page d'accueil
assert "Page d'accueil" in driver.title

# Fermer le navigateur
driver.quit()