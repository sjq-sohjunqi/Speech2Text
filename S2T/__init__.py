from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_paranoid import Paranoid
import pymysql
from werkzeug.utils import secure_filename

pymysql.install_as_MySQLdb()

S2T = Flask(__name__)
paranoid = Paranoid(S2T)
paranoid.redirect_view = '/'
S2T.config.from_object(Config)
db = SQLAlchemy(S2T)
bcrypt = Bcrypt(S2T)

UPLOAD_FOLDER = '.\\S2T\\tran_temp'
ALLOWED_EXTENSIONS = {'wav', 'aiff', 'aifc', 'flac'}
S2T.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from S2T import routes, models
