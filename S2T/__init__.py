from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

S2T = Flask(__name__)
S2T.config.from_object(Config)
db = SQLAlchemy(S2T)
bcrypt = Bcrypt(S2T)

from S2T import routes, models