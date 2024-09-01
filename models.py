from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Boiler(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    matricul = db.Column(db.String(100))  
    installation_date = db.Column(db.String(100))
    warranty_end = db.Column(db.String(100))
    client_name = db.Column(db.String(100))
    responsible_person = db.Column(db.String(100))
    last_modified = db.Column(db.String(100))

