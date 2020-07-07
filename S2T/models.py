from S2T import db, bcrypt
import datetime
from wtforms import StringField, TextField, Form
from wtforms.validators import DataRequired, Length


class User(db.Model):
	__tablename__ = 'users'

	username = db.Column(db.String(255), primary_key=True)
	password = db.Column(db.Text, nullable=False)
	name = db.Column(db.String(255))
	image = db.Column(db.String(255))
	bio = db.Column(db.String(255), nullable=True)
	works_at = db.Column(db.String(255), nullable=True)
	validated = db.Column(db.String(1))
	validate_str = db.Column(db.String(10), nullable=True)

	def __init__(self, username, password, name, validate_str):
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
		self.name = name
		self.validate_str = validate_str
		
		self.validated = 'N'
		
	def as_dict(self):
		return {'username': self.username, 'name':self.name}


class Transcripts(db.Model):
	__tablename__ = 'transcripts'

	name = db.Column(db.String(255), primary_key=True)
	username = db.Column(db.String(255), db.ForeignKey(
        'users.username'), primary_key=True)
	created_time = db.Column(db.DateTime, nullable=False)
	locked = db.Column(db.String(1), nullable=False)

	def __init__(self, name, username, locked):
		self.name = name
		self.username = username
		self.created_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		self.locked = locked


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

    group_id = db.Column(db.Integer, db.ForeignKey(
        'group_list.group_id'), primary_key=True)
    username = db.Column(db.String(255), db.ForeignKey(
        'users.username'), primary_key=True)
    role = db.Column(db.String(255))

    def __init__(self, group_id, username, role):
        self.group_id = group_id
        self.username = username
        self.role = role
	

class Shared_transcripts(db.Model):
	__tablename__ = 'shared_transcripts'
	
	share_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	name = db.Column(db.String(255), db.ForeignKey('transcripts.name'))
	owner = db.Column(db.String(255), db.ForeignKey('transcripts.username'))
	username = db.Column(db.String(255), db.ForeignKey('users.username'))
	permission = db.Column(db.String(2))
	
	def __init__(self, name, owner, username, permission):
		self.name = name
		self.owner = owner
		self.username = username
		self.permission = permission

class Group_shared_transcripts(db.Model):
	__tablename__ = 'group_shared_transcripts'
	
	share_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	name = db.Column(db.String(255), db.ForeignKey('transcripts.name'))
	owner = db.Column(db.String(255), db.ForeignKey('transcripts.username'))
	group_id = db.Column(db.Integer, db.ForeignKey('group_list.group_id'))
	permission = db.Column(db.String(2))
	allow_share = db.Column(db.String(1))
	
	def __init__(self, name, owner, group_id, permission, allow_share):
		self.name = name
		self.owner = owner
		self.group_id = group_id
		self.permission = permission
		self.allow_share = allow_share
		
class Group_share_details(db.Model):
	__tablename__ = 'group_share_details'
	
	gsd_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	gst_id = db.Column(db.Integer, db.ForeignKey('group_shared_transcripts.share_id'))
	username = db.Column(db.String(255), db.ForeignKey('users.username'))
	permission = db.Column(db.String(2))
	
	def __init__(self, gst_id, username, permission):
		self.gst_id = gst_id
		self.username = username
		self.permission = permission