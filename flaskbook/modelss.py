from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flaskbook import db, login_manager, app
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)     #ovde mora da stoji ime id!!!, jer u suportnom za login nece da radi, odnosno @login_manager ne moze da nadje id pod drugim imenom izgleda
    usernamee = db.Column(db.String(20), unique=True, nullable=False)
    emaill = db.Column(db.String(120), unique=True, nullable=False)
    picture = db.Column(db.String(20), nullable=False, default='default.jpg')
    passwordd = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')


    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


    def __repr__(self):
        return f"User('{self.usernamee}', '{self.emaill}', '{self.picture}')"


class Post(db.Model):
    idd = db.Column(db.Integer, primary_key=True)
    titlee = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    contentt = db.Column(db.Text, nullable=False)
    user_idd = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.titlee}', '{self.date_posted}')"

