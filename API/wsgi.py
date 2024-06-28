from API.flask_app.app import app
from API.flask_app.models import User, Asset
from werkzeug.security import generate_password_hash, check_password_hash
from API.flask_app.models import Asset_usage

# secret_key = app.config['SECRET_KEY'] # test
# print('secret key: ',secret_key) # test
from flask_cors import CORS
app.run(port=5000)
app.debug = True
CORS(app)

""" Testing Functions """
def add_user(username,email,password,country_code,phone,authy_id,authy_status):
    u = User(username=username, email=email,password=password,country_code=country_code,phone=phone,authy_id=authy_id,authy_status=authy_status)
    # u.set_password(password)
    db.session.add(u)
    db.session.commit()


def get_users():
    users = User.query.all()
    return users

