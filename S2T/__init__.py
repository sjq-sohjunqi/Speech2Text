from flask import Flask
from config import Config

S2T = Flask(__name__)
S2T.config.from_object(Config)

from S2T import routes