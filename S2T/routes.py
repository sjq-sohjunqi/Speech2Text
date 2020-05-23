import os
from flask import render_template, flash, redirect, url_for, session, request
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm, TranscribeForm, TranscriptForm
from werkzeug.utils import secure_filename

from S2T.models import User, Transcripts
from sqlalchemy.exc import IntegrityError

import speech_recognition as sr

from werkzeug.datastructures import MultiDict

@S2T.route('/', methods=['GET'])
@S2T.route('/index', methods=['GET'])
def index():
	return render_template('index.html', title='Home')

@S2T.route('/signup', methods=['GET', 'POST'])
def signup():
	form = SignUpForm()
	if form.validate_on_submit():
		try:
			new_user = User(form.data['username'], form.data['password'], form.data['name'])
			db.session.add(new_user)
			db.session.commit()
		except IntegrityError as e:
			flash('The email {} has already been taken', form.data['username'])
			return render_template('signup.html', title='Sign Up', form=form)
		
		flash('Signup successful for user {}'.format(form.username.data))
		return redirect(url_for('index'))
	
	return render_template('signup.html', title='Sign Up', form=form)

@S2T.route('/logout', methods=['GET'])
def logout():
	if not session.get('USER') is None:
		flash('Logged out successfully')
	session.pop('USER', None)
	session.pop('NAME', None)
	return redirect(url_for('index'))

@S2T.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		userObj = User.query.filter_by(username=form.data['username']).first()
		if userObj:
			authenticated_user = bcrypt.check_password_hash(userObj.password, form.data['password'])
			if authenticated_user:
				session['USER'] = userObj.username
				session['NAME'] = userObj.name
				return redirect(url_for('profile'))
				
			else:
				flash('Login unsuccessful for user {}'.format(form.username.data))
		else:
			flash('No such user {}'.format(form.username))
	return render_template('login.html', title='Sign In', form=form)
	
@S2T.route('/profile', methods=['GET', 'POST'])
def profile():
	passform = ChangePassForm()
	nameform = ChangeNameForm()
	if not session.get('USER') is None:
		user = session.get('USER')
		name = session.get('NAME')
		if passform.validate_on_submit():
			userObj = User.query.filter_by(username=user).first()
			'''User found'''
			if userObj:
				authenticated_user = bcrypt.check_password_hash(userObj.password, passform.data['oldpass'])
				'''Old password matches'''
				if authenticated_user:
					userObj.password = bcrypt.generate_password_hash(passform.data['newpass']).decode('UTF-8')
					try:
						'''Change password'''
						db.session.commit()
						flash('Password changed successfully!')
						return redirect(url_for('profile'))
					except IntegrityError as e:
						'''Error'''
						flash(e)
				else:
					'''Old password does not match'''
					flash('Old password does not match')
			else:
				'''No user found (unexpected)'''
				flash('An error has occurred; please sign in again')
				session.pop('USER', None)
				session.pop('NAME', None)
				return redirect(url_for('login'))
				
			return redirect(url_for('profile'))
			
		if nameform.validate_on_submit():
			userObj = User.query.filter_by(username=user).first()
			'''User found'''
			if userObj:
				userObj.name = nameform.data['newname']
				try:
					'''Change name'''
					db.session.commit()
					flash('Name changed successfully!')
					session['NAME'] = nameform.data['newname']
					return redirect(url_for('profile'))
				except IntegrityError as e:
						'''Error'''
						flash(e)
			else:
				'''No user found (unexpected)'''
				flash('An error has occurred; please sign in again')
				session.pop('USER', None)
				session.pop('NAME', None)
				return redirect(url_for('login'))
			
			return redirect(url_for('profile'))
		
		return render_template('profile.html', name=name, title=name+'\'s Page', passform=passform, nameform=nameform)
		
	else:
		return redirect(url_for('login'))
	

def convert(filepath):
	try:
		r = sr.Recognizer()
		file = sr.AudioFile(filepath)
		with file as source:
			'''Adjust for noise'''
			r.adjust_for_ambient_noise(source, duration=0.5)
			
			audio = r.record(source)
			
			return r.recognize_google(audio)
	except:
			return '%unrecognised%'


@S2T.route('/transcribe', methods=['GET', 'POST'])
def transcribe():
	transcribeForm = TranscribeForm()
	if transcribeForm.validate_on_submit():
		'''Check if post request has file'''
		file = transcribeForm.upload.data
		if file.filename == '':
			flash('Please select a file')
			return redirect(request.url)
		
		filename = secure_filename(file.filename)
		filepath = os.path.join(S2T.config['TEMP_FOLDER'], filename)
		file.save(filepath)
		flash('File Uploaded!')
		
		transcription = convert(filepath)
		if transcription == '%unrecognised%':
			transcriptForm = TranscriptForm()
			flash('Unable to transcript audio!')
		else:
			transcriptForm = TranscriptForm(formdata=MultiDict({'transcript':transcription}))
			flash('Audio Transcribed!')
		
		if session.get('USER') is None:
			return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
		else:
			return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))
	
		
	
	transcriptForm = TranscriptForm()
	if session.get('USER') is None:
		print("No user")
		return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
	else:
		return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))
		

@S2T.route('/save', methods=['POST'])
def save():
	print('Attempting to save transcript')
	transcribeForm = TranscribeForm()
	transcriptForm = TranscriptForm()
	
	print("submit pressed")
	try:
		'''Check if there is a duplicate entry'''
		transObj = Transcripts.query.filter_by(name=transcriptForm.data['name'], username=session.get('USER')).first()
		if transObj:
			print("Conflict in DB")
			flash('There is already a transcript with the same name!')
			'''return render_template('transcribe.html', form=form, transcriptForm=transcriptForm, saveTranscriptForm=saveTranscriptForm, user=session.get('USER'))'''
			return redirect(url_for('transcribe'))
			
		else:
			print('No conflicts in DB')
			filepath = os.path.join(S2T.config['STORAGE_FOLDER'], session.get('USER'), transcriptForm.data['name'])
			filedir = os.path.join(S2T.config['STORAGE_FOLDER'], session.get('USER'))
			
			'''Save new file'''
			if not os.path.exists(filedir):
				os.mkdir(filedir)
			
			print("Printing transcript:")
			'''transcriptText = transcriptform.transcript.get('1.0', 'end-1c')'''
			transcriptText = transcriptForm.transcript.data
			'''transcriptText = request.saveTranscriptForm.get('transcript')'''
			print(transcriptText)
			
			save_text = open(filepath, 'w')
			save_text.write(transcriptText)
			save_text.close()
			
			'''Update database'''
			new_transcript = Transcripts(name=transcriptForm.data['name'], filepath=filepath, username=session.get('USER'))
			db.session.add(new_transcript)
			db.session.commit()
			
			flash('File saved successfully!')
			
	except:
		flash('An error has occured; the transcript cannot be saved!')
		'''return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))'''
		return redirect(url_for('transcribe'))
	
	print("File saved")
	return redirect(url_for('transcribe'))