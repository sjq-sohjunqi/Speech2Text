from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_paranoid import Paranoid
import pymysql
from werkzeug.utils import secure_filename

pymysql.install_as_MySQLdb()

S2T = Flask(__name__)
S2T.debug = True
paranoid = Paranoid(S2T)
paranoid.redirect_view = '/'
S2T.config.from_object(Config)
db = SQLAlchemy(S2T)
bcrypt = Bcrypt(S2T)

'''Temp folder for conversions'''
S2T.config['TEMP_FOLDER'] = 'tran_temp'

'''Storage folder'''
S2T.config['STORAGE_FOLDER'] = 'transcripts'

''''Profile pictures folder'''
S2T.config['PROFILE_FOLDER'] = 'profiles'

''''Icons folder'''
S2T.config['ICONS_FOLDER'] = 'icons'

from S2T import routes, models
