from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember_me = BooleanField('Remember Me')
	submit = SubmitField('Sign In')
	
class SignUpForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	name = StringField('Name', validators=[DataRequired()])
	submit = SubmitField('Sign Up')

class ChangePassForm(FlaskForm):
	oldpass = PasswordField('Old Password', validators=[DataRequired()])
	newpass = PasswordField('New Password', validators=[DataRequired()])
	submit = SubmitField('Change Password')
	
class ChangeNameForm(FlaskForm):
	name = StringField('New Name', validators=[DataRequired()])