from API.flask_app import app, db, migrate
from flask import Flask
from API.flask_app.models import User, Asset
from werkzeug.security import generate_password_hash, check_password_hash
from API.flask_app.models import Asset_usage

# secret_key = app.config['SECRET_KEY'] # test
# print('secret key: ',secret_key) # test
from flask_cors import CORS

#app.run(port=8800)
app.debug = True
CORS(app)
import webview

#webview.create_window('My Flask App', 'http://localhost:8800')
#webview.start()
webview.create_window('Flask to exe', app)
webview.start()
""" Testing Functions """


def add_user(username, email, password, country_code, phone, authy_id, authy_status):
    u = User(username=username, email=email, password=password, country_code=country_code, phone=phone,
             authy_id=authy_id, authy_status=authy_status)
    # u.set_password(password)
    db.session.add(u)
    db.session.commit()


def get_users():
    users = User.query.all()
    return users


def create_app() -> object:
    """Application-factory pattern"""
    db.init_app(app)
    migrate.init_app(app, db)
    return app


""" testion instances """
# test_app = create_app()

""" Add user """
# add_user(username='zakaria', email='zakaria.ghalem@brightway.fr',password='1234',country_code=33,phone='755641974',authy_id=419390294,authy_status='approved')
# add_user(username='susan', email='susan@example.com',password='susan1')
# add_user(username='user1', email='user1@test.com',password='user1pswd')

""" get all users """
# users = get_users()
# print(users)
# print(type(users[0]))
# for u in users:
#     print(u.id, u.username)

""" Haching passwords """
# hash = generate_password_hash("foobar")
# print(type(hash))
# print(hash)
# pwhash = 'pbkdf2:sha256:260000$boRvDWfg4uJRm6TB$d8343e834f229a94fddb595d3841b6cb9f06320309146dce0905433f69734515'
# pwhash = 'pbkdf2:sha256:260000$i3n6B46ZJ4oNvgIC$1f76116a2d22a3ea8ac3e04c7efb9c73f2cbe6e074656ff85e8a6716b659ec8a'
# print(check_password_hash(pwhash,'foobar'))

# u = User(username='user1', email='user1@test.com')
# u.set_password('user1pswd')
# print(u.check_password('mypassword'))

""" get user assets """
# username = 'ZGH'
# user = User.query.filter_by(username=username).first()
# asset_list = user.get_assets()
# for asset in asset_list:
#     print('asset: ',asset['asset_ref'])
#     for cpe in asset['cpes']:
#         print('\t',cpe)

""" filter with 3 arguments """
# a_u = Asset_usage.query.filter_by(cpe='cpe:2.3:a:_pacestar_software:lanflow:6.0:*:*:*:*:*:*:* ',groupe=8,asset_ref='BRL004').first()
# if a_u:
#     print(a_u.id)


""" Update object """
# asset = Asset.query.filter_by(asset_ref = 'Test001', groupe = 10).first()
# asset.service = 'SI'
# db.session.commit()
# print(asset.service)
