import os

class Config(object):
	SECRET_KEY = '\xf2\xa1/\x9e\xf2B\xc5N\x95\xd2\x8ey\x00a\xc2\x93C\x01$\x16\x92\xf69\xfd'
	SQLALCHEMY_DATABASE_URI = 'mysql://root:root@127.0.0.1:3306/speech2text'
	SQLALCHEMY_TRACK_MODIFICATIONS = False