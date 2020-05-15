from S2T import db, bcrypt

class User(db.Model):
	__tablename__ = 'users'
	
	username = db.Column(db.String(255), primary_key=True)
	password = db.Column(db.Text)
	name = db.Column(db.String(255))
	
	def __init__(self, username, password, name):
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
		self.name = name