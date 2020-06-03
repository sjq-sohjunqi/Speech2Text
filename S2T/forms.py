from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextField
from wtforms.validators import DataRequired, Regexp, Length, Email, EqualTo, InputRequired
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.widgets import TextArea


class LoginForm(FlaskForm):
    username = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


class SignUpForm(FlaskForm):
    username = StringField('Email', validators=[DataRequired(), Email(
    ), Length(max=255, message='Email address is too long')])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=2, max=255)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    name = StringField('Name', validators=[DataRequired(
    ), Length(min=3, max=255)])
    submit = SubmitField('Sign Up')


class ChangePassForm(FlaskForm):
    oldpass = PasswordField('Old Password', validators=[DataRequired()])
    newpass = PasswordField('New Password', validators=[
                            DataRequired(), Length(max=255)])
    submit = SubmitField('Change Password')


class ChangeNameForm(FlaskForm):
    newname = StringField('New Name', validators=[DataRequired()])
    submit = SubmitField('Change Name')


class TranscribeForm(FlaskForm):
    upload = FileField('Upload Audio', validators=[FileRequired(), FileAllowed(
        ['wav'], 'Only WAV files are supported')])
    submit = SubmitField('Transcribe')


class TranscriptForm(FlaskForm):
	transcript = TextField('transcript', widget=TextArea())
	name = StringField('Save Transcript As', validators=[InputRequired(), Regexp('^((?![\"\*\:\<\>\?\/\\\|]).)*$', message='A valid filename cannot have " * : < > ? / \ or |')])
	save = SubmitField('Save Transcript')
	
class GroupForm(FlaskForm):
	grpname = StringField('Group Name', validators=[DataRequired(), Length(max=255)])
	add = SubmitField('Add New Group')
	
