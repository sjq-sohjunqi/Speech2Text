from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Regexp, Length
from flask_wtf.file import FileField, FileAllowed, FileRequired

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Sign In')
	
class SignUpForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Regexp('[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', message='Please enter a valid email address'), Length(max=255, message='Email address is too long')])
	password = PasswordField('Password', validators=[DataRequired(), Length(max=255, message='Password is too long')])
	name = StringField('Name', validators=[DataRequired(), Length(max=255, message='Name is too long')])
	submit = SubmitField('Sign Up')

class ChangePassForm(FlaskForm):
	oldpass = PasswordField('Old Password', validators=[DataRequired()])
	newpass = PasswordField('New Password', validators=[DataRequired(), Length(max=255, message='New password is too long')])
	submit = SubmitField('Change Password')
	
class ChangeNameForm(FlaskForm):
	newname = StringField('New Name', validators=[DataRequired()])
	submit = SubmitField('Change Name')
	
class TranscribeForm(FlaskForm):
	upload = FileField('Upload Audio', validators=[FileRequired(), FileAllowed(['wav', 'mp3'], 'Only wav and mp3 files are supported')])
	submit = SubmitField('Transcribe')
	