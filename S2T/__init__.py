from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_paranoid import Paranoid
import pymysql
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message

pymysql.install_as_MySQLdb()

S2T = Flask(__name__)
S2T.debug = True
paranoid = Paranoid(S2T)
paranoid.redirect_view = '/'
S2T.config.from_object(Config)
db = SQLAlchemy(S2T)
bcrypt = Bcrypt(S2T)

'''Change when in production'''
#S2T.config['SERVER_NAME'] = '127.0.0.1:5000'
S2T.config['SERVER_NAME'] = 'sohjunqi.pythonanywhere.com'

'''Temp folder for conversions'''
S2T.config['TEMP_FOLDER'] = 'tran_temp'

'''Storage folder'''
S2T.config['STORAGE_FOLDER'] = 'transcripts'

''''Profile pictures folder'''
S2T.config['PROFILE_FOLDER'] = 'profiles'

''''Icons folder'''
S2T.config['ICONS_FOLDER'] = 'icons'

''''Help Images folder'''
S2T.config['HELP_FOLDER'] = 'help_img'

'''Mail configurations'''
S2T.config['MAIL_SERVER']='smtp.gmail.com'
S2T.config['MAIL_PORT'] = 465
S2T.config['MAIL_USERNAME'] = 'speechtextapplication@gmail.com'
S2T.config['MAIL_PASSWORD'] = "&sz6H5br~LZ/')7V"
S2T.config['MAIL_USE_TLS'] = False
S2T.config['MAIL_USE_SSL'] = True
mail = Mail(S2T)

from S2T import routes, models
