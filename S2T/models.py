from S2T import db, bcrypt
import datetime

class User(db.Model):
	__tablename__ = 'users'
	
	username = db.Column(db.String(255), primary_key=True)
	password = db.Column(db.Text, nullable=False)
	name = db.Column(db.String(255))
	
	def __init__(self, username, password, name):
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
		self.name = name
		
class Transcripts(db.Model):
	__tablename__ = 'transcripts'
	
	name = db.Column(db.String(255), primary_key=True)
	filepath = db.Column(db.String(255), nullable=False)
	username = db.Column(db.String(255), db.ForeignKey('users.username'), primary_key=True)
	created_time = db.Column(db.DateTime, nullable=False)
	
	def __init__(self, name, filepath, username):
		self.name = name
		self.filepath = filepath
		self.username = username
		self.created_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	
	