import os

class Config:
    # SESSION_COOKIE_SAMESITE = 'None'
    # SESSION_COOKIE_SECURE = True
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///boilers.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
