import os
class configuracion(object):
     SECRET_KEY = os.environ.get('SECRET_KEY') or 'password'
     SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'