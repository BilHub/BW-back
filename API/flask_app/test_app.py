import pytest
import requests

from API.flask_mega_tuto import create_app
from API.flask_app.models import User
import jwt
from flask_jwt_extended import create_access_token
import json


# from API.flask_app import app


class TestWebApplication:
    app = create_app()  # container object for test applications #

    @pytest.fixture
    def initialize_app(self):
        app = create_app()
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        app.testing = True
        self.app = app

    #@pytest.fixture()
    #def token(self):
        #response = requests.post('http://localhost:8800/token',json={'username':'zgh', 'password':'1234'})
        #token = response.json()['access_token']
        #print("jwt",token)
        #return token
    @pytest.fixture()
    def access_token(self):
        access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY4MDA5MDM0NCwianRpIjoiM2E1YjllYjUtYzQzOS00NjhhLTg2ODgtYmM0NzkyN2FkMTc3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNjgwMDkwMzQ0LCJleHAiOjE2ODAyNjMxNDR9.lJ2sQcXK5nvZNPXzVwzV-IW9A6Sg7pVOgC8xVpmhzeU"
        return access_token

    def test_protected_endpoint(self, access_token):
        headers = {'Authorization': 'Bearer ' + access_token}
        response = requests.get('http://localhost:8800/list-unread-tickets', headers=headers)
        assert response.status_code

    #def test_hello_get(self, initialize_app):
        #with self.app.test_client() as client:
            #response = client.get('/api-test')
            #print("res", response)
        #assert response.status_code == 200




