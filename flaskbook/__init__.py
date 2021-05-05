import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail



app = Flask (__name__)
app.config['SECRET_KEY'] = '889bfedeee8f02fbd4b0d8d68b737a90'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  #sa ovim kazemo da kada ukucamo u browser '/profile' da nas odvede do login funkcije, odnosno login page
login_manager.login_message_category = 'info' # ovo sluzi da bi se drugacije prikazala poruka kada treba da se ulogujes direktno u browser da bi video 'profile' i ovaj info je iz bootstrap-a, poruka je (Please log in to access this page.)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)


from flaskbook import routes