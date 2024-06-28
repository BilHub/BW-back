import pytest
import jwt
import json

from API.flask_app.models import reset_password_token
from API.flask_mega_tuto import create_app
import re


def is_valid_password(password):
    # Vérifier la longueur du mot de passe
    if len(password) < 8:
        return False

    # Vérifier s'il y a au moins une lettre minuscule, une lettre majuscule et un chiffre
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    # Vérifier s'il y a au moins un caractère spécial
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    # Si toutes les vérifications passent, le mot de passe est considéré comme valide
    return True


def test_valid_password():
    assert is_valid_password('myPassw0rd!') == True
    assert is_valid_password('1234') == False


@pytest.fixture()
def client():
    app = create_app()
    with app.test_client() as client:
        yield client


@pytest.fixture()
def access_token(client):
    response = client.post('/token', data=json.dumps({'username': 'zgh', 'password': '1234'}),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.data)
    return data["token"]


def test_login(client):
    url = '/token'
    data = {'username': 'zgh', 'password': '1234'}
    response = client.post(url, json=data)
    assert response.status_code == 200
    assert 'token' in response.json


def test_invalid_login_password(client):
    # Test de connexion échouée avec un mot de passe invalide
    data = {"username": "zgh", "password": "123489"}
    response = client.post('/token', data=json.dumps(data), content_type="application/json")
    assert response.status_code == 401
    assert response.json["msg"] == "Identifiant ou mot de passe incorrect"

def test_unread_ticket(client, access_token):
    response = client.get('/list-unread-tickets', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["count"] == 299
def test_detail_asset(client, access_token):
    response = client.get('/asset-detail-api/CML001', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]['collaborateur'] == 'olivier'
    assert data[1]['importance'] == 'Critique'
    assert data[2]['service'] == 'Secops'

def test_add_service(client, access_token):
    data = {"desciption": "pytest", "localisation": "Paris", "name": "ptest", "responsable": "suzanne"}
    response = client.post('/service-api/add', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 404
    # assert response.json["success"] == "Service ajouté avec succès


def test_add_asset(client, access_token):
    data = {"asset_ref": "CM6", "service": "Secops", "importance": "1"}
    response = client.post('/asset-api/add', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 400
    #assert response.json["asset"] == "success"


def test_liste_service(client, access_token):
    response = client.get('/service/lists', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    #data = json.loads(response.data)
    #assert len(data)==6
    #assert data[0]['desciption'] == 'service de direction'
    #assert data[1]['id'] == '1'
    #assert data[2]['localisation'] == 'paris'
    #assert data[3]['manager'] == 'olivier'
    #assert data[4]['name'] == 'DSI'
    #assert data[5]['responsable'] == 'Suzanne'

def test_list_collab(client, access_token):
    response = client.get('/liste-collab', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200


def test_list_products(client, access_token):
    response = client.get('/product-api/list-all', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200

def test_service_add(client, access_token):
    data = {"localisation": "Ile de france", "description": "Python test API", "collab": "suzanne", "name": "pytest"}
    response = client.post('/service-api/add', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 404
    # assert response.json["success"] == "Service ajouté avec succès"

def test_update_ticket(client, access_token):
    data = {"ticket_id":"2022480", "status":"Fermé", "comment":"pytest ", "action":"pytesttest"}
    response = client.post('/ticket-modify-api', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 404
    #assert response.json["message"] == "success"

def test_asset_api_get(client,access_token):
    response = client.get('/asset-api-get', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200

def test_history_ticket(client, access_token):
    response = client.get('/ticket-ticket-history/2022479', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200

def test_list_assets(client, access_token):
    response = client.get('/asset-api/list-all', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200

def test_detail_user(client, access_token):
    response = client.get('/profile-detail-get-api', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200

def test_history_ticket(client, access_token):
    response = client.get('/tickets-history/list-all', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200


def test_ticket(client,access_token):
    response= client.get('/tickets-api-get', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
def test_detail_ticket(client, access_token):
    response = client.get('/ticket-detail-api/2022476', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200






def test_list_ticket(client, access_token):
    response = client.get('/tickets-api-get', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
def test_change_password(client, access_token):
    data = {"old_password": "Brightway@Brightwatch2023!", "password1": "Lavieestbelle*0107",
            "password2": "Lavieestbelle*0107"}
    response = client.post('/user/passwordapi', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 400
    #assert response.json["msgasset/add-product-api"] == "ancien password"

def test_detail_asset(client, access_token):
    response = client.get('/asset-detail-api/CML002', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200


def test_add_product(client, access_token):
    data = {"asset_ref": "BRL017",
            "name": "Product",
            "version": "3.0",
            "type": " Os ",
            "producer": "microsoft_corporation"}
    response = client.post('/asset/add-product-api', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 400  # Bad request limite autorisé est atteinte
    #assert response.json["error"] == "Produit existe déjà"

def test_update_asset(client, access_token):
    data = {"id":"1",
        "asset_ref": "CML001",
        "importance": "1",
        "service": "Secops",
        "collab": "olivier"}
    response = client.post('/asset-api/update', headers={'Authorization': f'Bearer {access_token}'}, json=data)
    assert response.status_code == 200
    assert response.json["success"] == "asset modifié avec succès"

def test_update_status(client, access_token):
        data = {"ticket_id":"2022479"}
        response = client.post('/modify-ticket-status', headers={'Authorization': f'Bearer {access_token}'}, json=data)
        assert response.status_code == 404
        assert response.json["message"] == "error"

#################################Collab##################
@pytest.fixture()
def access_token_collab(client):
    response = client.post('/token', data=json.dumps({'username': 'jhw', 'password': '1234'}),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.data)
    return data["token"]
def test_login_collab(client):
    url = '/token'
    data = {'username': 'jhw', 'password': '1234'}
    response = client.post(url, json=data)
    assert response.status_code == 200

def test_list_service_collab(client, access_token_collab):
    response = client.get('/service/lists', headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200

def test_user_collab(client, access_token_collab):
    response = client.get('/profile-detail-get-api', headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200

def test_actif_collab(client, access_token_collab):
    response = client.get('/asset-api-get', headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200
def test_ticke_collab(client, access_token_collab):
    response = client.get('/user-tickets-api-get', headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200
def test_product_api(client, access_token_collab):
    response = client.get('/product-api/list-all', headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200

def test_change_passwoard(client, access_token_collab):
    url = '/user/passwordapi'
    data = {"old_password":"1234",
    "password1":"1234",
    "password2":"1234"}
    response = client.post(url, json=data , headers={'Authorization': f'Bearer {access_token_collab}'})
    assert response.status_code == 200