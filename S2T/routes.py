import os
from flask import render_template, flash, redirect, url_for, session, request, send_from_directory
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm, TranscribeForm, TranscriptForm, GroupForm
from werkzeug.utils import secure_filename

from S2T.models import User, Transcripts, Groups, Group_roles
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
		
		'''Display all transcripts of user'''
		transObj = Transcripts.query.filter_by(username=user).all()
		transTable = []
		for tran in transObj:
			transTable.append(tran)
			
		
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
		
		return render_template('profile.html', name=name, title=name+'\'s Page', passform=passform, nameform=nameform, transcripts=transTable)
		
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
		filepath = os.path.join(S2T.root_path, S2T.config['TEMP_FOLDER'], filename)
		
		try:
			file.save(filepath)
		except:
			flash('Unable to upload file')
			return redirect(request.url)
		
		
		transcription = convert(filepath)
		if transcription == '%unrecognised%':
			transcriptForm = TranscriptForm()
			flash('Unable to transcript audio!')
		else:
			transcriptForm = TranscriptForm(formdata=MultiDict({'transcript':transcription}))
			flash('Audio Transcribed!')
			
			'''Remove file from temp folder'''
			os.remove(filepath)
		
		if session.get('USER') is None:
			return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
		else:
			return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))
	
	'''Check if transcript has previously written data'''
	if request.method == 'GET':
		
		transcriptFormName = session.get('transcriptFormName', None)
		transcriptFormNameErr = session.get('transcriptFormNameErr', None)
		transcriptFormTrans = session.get('transcriptFormTrans', None)
		
		if transcriptFormNameErr:
			transcriptForm = TranscriptForm(formdata=MultiDict({'name':transcriptFormName, 'transcript':transcriptFormTrans}))
			transcriptForm.name.errors = transcriptFormNameErr
			
			session.pop('transcriptFormName')
			session.pop('transcriptFormNameErr')
			session.pop('transcriptFormTrans')
		else:
			transcriptForm = TranscriptForm()
	else:
		transcriptForm = TranscriptForm()
	
	
	if session.get('USER') is None:
		return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
	else:
		return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))
		

@S2T.route('/save', methods=['POST'])
def save():
	transcriptForm = TranscriptForm()

	if transcriptForm.validate_on_submit():
		
		'''Save transcript in session for redirect'''
		transcriptText = transcriptForm.transcript.data
		
		try:
			'''Check if there is a duplicate entry'''
			transObj = Transcripts.query.filter_by(name=transcriptForm.data['name'], username=session.get('USER')).first()
			if transObj:
				flash('There is already a transcript with the same name!')
				return redirect(url_for('transcribe'))
				
			else:
				
				filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], session.get('USER'), transcriptForm.data['name'])
				filedir = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], session.get('USER'))
				
				'''Save new file'''
				if not os.path.exists(filedir):
					os.mkdir(filedir)
				
				save_text = open(filepath, 'w')
				save_text.write(transcriptText)
				save_text.close()
				
				'''Update database'''
				new_transcript = Transcripts(name=transcriptForm.data['name'], username=session.get('USER'))
				db.session.add(new_transcript)
				db.session.commit()
				
				flash('File saved successfully!')
				
		except:
			flash('An error has occured; the transcript cannot be saved!')
			return redirect(url_for('transcribe'))
	
	session['transcriptFormName'] = transcriptForm.name.data
	session['transcriptFormNameErr'] = transcriptForm.name.errors
	session['transcriptFormTrans'] = transcriptForm.transcript.data
	
	return redirect(url_for('transcribe'))
	
@S2T.route('/download/<string:filename>', methods=['GET'])
def download(filename):
	'''Check if logged in'''
	if not session.get('USER') is None:
		user = session.get('USER')
		
		try:
			transObj = Transcripts.query.filter_by(name=filename, username=user).first()
			if transObj:
				filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], user)
				return send_from_directory(directory=filepath, filename=filename)
			else:
				flash('File could not be found on server!')
				return redirect(url_for('profile'))
		except:
			flash('File could not be found on server!')
			return redirect(url_for('profile'))
		
	else:
		return redirect(url_for('login'))
	
@S2T.route('/delete/<string:filename>', methods=['GET'])
def delete(filename):
	'''Check if logged in'''
	if not session.get('USER') is None:
		user = session.get('USER')
		
		try:
			transObj = Transcripts.query.filter_by(name=filename, username=user).first()
			if transObj:
				filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], user)
				
				'''Remove file from database'''
				db.session.delete(transObj)
				db.session.commit()
				
				'''Remove file from filesystem'''
				os.remove(os.path.join(filepath, filename))
				flash('File successfully deleted!')
				
			else:
				flash('File cannot be found on server!')
				
		except IntegrityError as e:
			flash('File cannot be found on server!')
		
	else:
		return redirect(url_for('login'))
		
	return redirect(url_for('profile'))
	
@S2T.route('/edit/<string:old_filename>', methods=['GET', 'POST'])
def edit(old_filename):
	
	transcriptForm = TranscriptForm()
	
	'''Check if logged in'''
	if not session.get('USER') is None:
		
		user = session.get('USER')
		filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], user)
		
		if transcriptForm.validate_on_submit():
			'''Update database with new name'''
			try:
				transObj = Transcripts.query.filter_by(name=old_filename, username=user).first()
				transObj.name = transcriptForm.data['name']
				
				db.session.commit()
			
			except:
				flash('Unable to update database!')
				return redirect(url_for('profile'))
			
			'''Override current file with new contents'''
			try:
				os.remove(os.path.join(filepath, old_filename))
				
				save_text = open(os.path.join(filepath, transcriptForm.data['name']), 'w')
				save_text.write(transcriptForm.data['transcript'])
				save_text.close()
				
				flash('File Edited!')
				return redirect(url_for('profile'))
				
			except:
				flash('Unable to save file!')
				return redirect(url_for('profile'))
		
		'''Populate transcript text area with contents'''
		try:
			with open(os.path.join(filepath, old_filename), 'r') as f:
				transcription = f.read()
				transcriptForm = TranscriptForm(formdata=MultiDict({'transcript':transcription, 'name':old_filename}))
		except:
			flash('Unable to read file!')
			return redirect(url_for('profile'))
		
		return render_template('edit.html', transcriptForm=transcriptForm, old_filename=old_filename)
		
	else:
		return redirect(url_for('login'))
	
	
@S2T.route('/groups', methods=['GET', 'POST'])
def groups():
	groupform = GroupForm()
	
	'''Check if logged in'''
	if not session.get('USER') is None:
		
		user = session.get('USER')
		
		'''Get all groups under the user'''
		grpsObj = Groups.query.filter_by(username=user).all()
		grpsTable = []
		for grp in grpsObj:
			grpsTable.append(grp)
		
		'''If add new group form submitted'''
		if groupform.validate_on_submit():
			try:
				'''Check if there is already a group with the same name'''
				existing_grp = Groups.query.filter_by(group_name=groupform.data['grpname'], username=user).first()
				if existing_grp:
					flash('You already have a group with that name!')
				else:
					new_grp = Groups(groupform.data['grpname'], user)
					db.session.add(new_grp)
					db.session.commit()
					flash('Group successfully created!')
					
			except IntegrityError as e:
				print(e)
				flash('Unable to create new group!')
		
		return render_template('groups.html', groupform=groupform, grpsTable=grpsTable)
		
	else:
		return redirect(url_for('login'))
		
	