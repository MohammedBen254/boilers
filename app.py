import os
from flask import Flask
from config import Config
from models import db, User
from routes import main_routes
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import timedelta

app = Flask(__name__)
CORS(app)

app.config.from_object(Config)
# app.config['SESSION_COOKIE_DOMAIN'] = 'boilers-pi.vercel.app'
# app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # 'Lax' or 'None' for cross-site cookies
# app.config['SESSION_COOKIE_SECURE'] = True  # Ensure this is True if using HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Set session timeout to 1 hour

migrate = Migrate(app, db)  # assuming `app` is your Flask app and `db` is your SQLAlchemy instance
db.init_app(app)

app.register_blueprint(main_routes)

if __name__ == "__main__":
    app.run()
# host='0.0.0.0', port='50000'
