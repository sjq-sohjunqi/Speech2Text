from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextField, SelectField
from wtforms.validators import DataRequired, Regexp, Length, Email, EqualTo, InputRequired
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.widgets import TextArea


class LoginForm(FlaskForm):
    username = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


class SignUpForm(FlaskForm):
	username = StringField('Email', validators=[DataRequired(), Email(), Length(max=255, message='Email address is too long')])
	password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=255)])
	confirm_password = PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password')])
	name = StringField('Name', validators=[DataRequired(), Length(min=3, max=255)])
	submit = SubmitField('Sign Up')

class UploadImageForm(FlaskForm):
	img = FileField('Change Profile Picture', validators=[FileRequired(), FileAllowed(['jpg', 'png'], 'Only JPG or PNG files are supported')])
	chg_img = SubmitField()

class ChangeBioForm(FlaskForm):
	bio = TextField('Biography', widget=TextArea())
	chg_bio = SubmitField()
	
class ChangeWorksAtForm(FlaskForm):
	works_at = StringField('Works At', validators=[Length(max=255)])
	chg_wa = SubmitField()
	
class ChangePassForm(FlaskForm):
    oldpass = PasswordField('Old Password', validators=[DataRequired()])
    newpass = PasswordField('New Password', validators=[
                            DataRequired(), Length(max=255)])
    chg_passwd = SubmitField('Change Password')


class ChangeNameForm(FlaskForm):
    newname = StringField('New Name', validators=[DataRequired(), Length(max=255)])
    chg_name = SubmitField('Change Name')


class TranscribeForm(FlaskForm):
	upload = FileField('Upload Audio', validators=[FileRequired(), FileAllowed(['wav'], 'Only WAV files are supported')])
	language = SelectField('Audio Language', choices=[('en-SG','English (SG)'), ('en-GB','English (UK)'), ('en-US','English (US)'), ('zh','Mandarin (Simplified, China)'), ('zh-TW','Mandarin (Traditional, Taiwan)'), ('ms-MY','Malay (Malaysia)'), ('ta-SG','Tamil (Singapore)'), ('ta-IN','Tamil (India)'), ('ta-LK','Tamil (Sri Lanka)')])
	submit = SubmitField('Transcribe')


class TranscriptForm(FlaskForm):
	transcript = TextField('transcript', widget=TextArea())
	name = StringField('Save Transcript As', validators=[InputRequired(), Regexp('^((?![\"\*\:\<\>\?\/\\\|]).)*$', message='A valid filename cannot have " * : < > ? / \ or |')])
	annotation = TextField('annotation', widget=TextArea())
	save = SubmitField('Save Transcript')
	
class GroupForm(FlaskForm):
	grpname = StringField('Group Name', validators=[DataRequired(), Length(max=255)])
	add = SubmitField('Create New Group')
