from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
import datetime as dti
import os

# Configuration
class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    # Assuming MySQL is your database
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'scout'
    MYSQL_PASSWORD = '2.PGV_db'
    MYSQL_DB = 'pgvdb_schema5'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql://' + MYSQL_USER + ':' + MYSQL_PASSWORD + '@' + MYSQL_HOST + ':3306/' + MYSQL_DB
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    JWT_SECRET_KEY = "super-secret"

app = Flask("__name__")
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
jwt = JWTManager(app)
#CORS(app)
CORS(app, resources={r"/*": {
        "origins": "*",  # Allows all origins
        "methods": ["OPTIONS", "GET", "POST", "DELETE", "PUT"],  # Specify other methods needed
        "allow_headers": [
            "Authorization",
            "Content-Type"
        ]
    }})

### this par was modified by commenting the imports and adding the condition

from .routes import *
from .models import *

#if __name__ == '__main__':
#    app.run(debug=True, host='0.0.0.0', port=5000)