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
	username = db.Column(db.String(255), db.ForeignKey('users.username'), primary_key=True)
	created_time = db.Column(db.DateTime, nullable=False)
	
	def __init__(self, name, username):
		self.name = name
		self.username = username
		self.created_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	

class Groups(db.Model):
	__tablename__ = 'group_list'
	
	group_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	group_name = db.Column(db.String(255))
	username = db.Column(db.String(255), db.ForeignKey('users.username'))
	
	def __init__(self, group_name, username):
		self.group_name = group_name
		self.username = username
		
class Group_roles(db.Model):
	__tablename__ = 'group_roles'
	
	group_id = db.Column(db.Integer, primary_key=True, db.ForeignKey('group_list.group_id'))
	username = db.Column(db.String(255), primary_key=True, db.ForeignKey('users.username'))
	role = db.Column(db.String(255))
	
	def __init__(self, group_id, username, role)
		self.group_id = group_id
		self.username = username
		self.role = role