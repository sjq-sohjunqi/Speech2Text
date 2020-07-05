import os
from flask import render_template, flash, redirect, url_for, session, request, send_from_directory, jsonify, json
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm, TranscribeForm, TranscriptForm, GroupForm, UploadImageForm, ChangeBioForm, ChangeWorksAtForm
from werkzeug.utils import secure_filename

from S2T.models import User, Transcripts, Groups, Group_roles, Shared_transcripts, Group_shared_transcripts, Group_share_details
from sqlalchemy.exc import IntegrityError

'''Libraries for Google Cloud Speech-to-Text'''
from pydub import AudioSegment
import io
import os
from google.cloud import speech
from google.cloud.speech import enums
from google.cloud.speech import types
import wave
from google.cloud import storage

#import speech_recognition as sr

from werkzeug.datastructures import MultiDict

'''CLEARING CACHE FOR PROFILE PIC TO WORK IMMEDIATELY - REMOVE IF MAKING ERRORS'''
@S2T.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

@S2T.errorhandler(404)
def pageNotFound(error):
    return render_template('error.html', title='Error')

@S2T.errorhandler(500)
def pageNotFound(error):
    return render_template('error.html', title='Error')

@S2T.route('/', methods=['GET'])
@S2T.route('/index', methods=['GET'])
def index():
    return render_template('index.html', title='Home')


@S2T.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        try:
            new_user = User(form.data['username'],
                            form.data['password'], form.data['name'])
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:
            flash('The email {} has already been taken'.format(form.username.data),'warning')
            return render_template('signup.html', title='Sign Up', form=form)

        flash('Signup successful for user {}'.format(form.username.data), 'success')
        return redirect(url_for('index'))

    return render_template('signup.html', title='Sign Up', form=form)


@S2T.route('/logout', methods=['GET'])
def logout():
    if not session.get('USER') is None:
        flash('Logged out successfully','success')
    session.pop('USER', None)
    session.pop('NAME', None)
    return redirect(url_for('index'))


@S2T.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        userObj = User.query.filter_by(username=form.data['username']).first()
        if userObj:
            authenticated_user = bcrypt.check_password_hash(
                userObj.password, form.data['password'])
            if authenticated_user:
                session['USER'] = userObj.username
                session['NAME'] = userObj.name
                return redirect(url_for('index'))

            else:
                flash('Login unsuccessful for user {}'.format(form.username.data),'danger')
        else:
            flash('No such user {}'.format(form.data['username']), 'warning')
    return render_template('login.html', title='Sign In', form=form)

@S2T.route('/pictures/<string:username>', methods=['GET'])
def pictures(username):
	try:
		user = User.query.filter_by(username=username).first()
		if user:
			if not user.image is None:
				filepath = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'], user.username)
				return send_from_directory(filepath, user.image)
		
		filepath = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'])
		return send_from_directory(filepath, 'default.jpg')
	except IntegrityError as e:
		print(e)
		
		filepath = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'])
		return send_from_directory(filepath, 'default.jpg')
	
@S2T.route('/edit_icon', methods=['GET'])
def edit_icon():
	filepath = os.path.join(S2T.root_path, S2T.config['ICONS_FOLDER'])
	return send_from_directory(filepath, 'edit_icon.png')
	
@S2T.route('/save_icon', methods=['GET'])
def save_icon():
	filepath = os.path.join(S2T.root_path, S2T.config['ICONS_FOLDER'])
	return send_from_directory(filepath, 'save_icon.png')


@S2T.route('/public_profile/<string:username>', methods=['GET'])
def public_profile(username):
	if not session.get('USER') is None:
		
		try:
			userObj = User.query.filter_by(username=username).first()
			if userObj:
				
				name = userObj.name
				bio = userObj.bio
				works_at = userObj.works_at
				picture = url_for('pictures', username=username)
				
				return render_template('public_profile.html', name=name, bio=bio, works_at=works_at, title=name + '\'s Page', picture=picture)
			
			else:
				flash("Unabel to view user's profile", "warning")
				return redirect(url_for('index'))
			
		except IntegrityError as e:
			print(e)
			flash("Unabel to view user's profile", "warning")
			return redirect(url_for('index'))
		
	else:
		return redirect(url_for('login'))

@S2T.route('/profile', methods=['GET', 'POST'])
def profile():
	passform = ChangePassForm()
	nameform = ChangeNameForm()
	changebioform = ChangeBioForm()
	changeworksatform = ChangeWorksAtForm()
	
	uploadImageForm = UploadImageForm()
	picture = url_for('pictures', username='default')
	
	if not session.get('USER') is None:
		user = session.get('USER')
		name = session.get('NAME')
		picture = url_for('pictures', username=user)
		bio = None
		works_at = None
		
		save_icon = url_for("save_icon")
		edit_icon = url_for("edit_icon")
		
		
		'''Get user object'''
		userObj = User.query.filter_by(username=user).first()
		if userObj:
			
			'''Get user's bio and works_at'''
			bio = userObj.bio
			works_at = userObj.works_at 
			
			if 'chg_bio' in request.form and changebioform.validate_on_submit():
				'''Get updated bio'''
				new_bio = changebioform.bio.data
				userObj.bio = new_bio
				
				db.session.add(userObj)
				db.session.commit()
				
				flash("Biography updated", "success")
				return redirect(url_for("profile"))
				
			if 'chg_wa' in request.form and changeworksatform.validate_on_submit():
				'''Get updated works_at'''
				new_wa = changeworksatform.works_at.data
				userObj.works_at = new_wa
				
				db.session.add(userObj)
				db.session.commit()
				
				flash("Works At updated", "success")
				return redirect(url_for("profile"))
			
			if 'chg_img' in request.form and uploadImageForm.validate_on_submit():
				'''Get file uploaded'''
				file = uploadImageForm.img.data
				if file.filename == '':
					flash('Error when changing profile picture','warning')
					return redirect(url_for("profile"))
				
				filename = secure_filename(file.filename)
				filepath = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'], user, filename)
				filedir = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'], user)
				
				try:
					'''Remove previous file'''
					oldImgName = userObj.image
					
					if not oldImgName is None:
						oldfilepath = os.path.join(S2T.root_path, S2T.config['PROFILE_FOLDER'], user, oldImgName)
						os.remove(oldfilepath)
						
					
					if not os.path.exists(filedir):
						os.mkdir(filedir)
					
					file.save(filepath)
					
					try:
						'''Update database for image uploaded'''
						userObj.image = file.filename
						db.session.add(userObj)
						db.session.commit()
						
						flash("Profile picture updated", "success")
						
						return redirect(url_for("profile"))
						
					except IntegrityError as e:
						print(e)
						flash('A database error has occurred', "warning")
					
				except:
					flash('Unable to upload image','warning')
				

				return redirect(url_for("profile"))
			
			if "chg_passwd" in request.form and passform.validate_on_submit():

				authenticated_user = bcrypt.check_password_hash(userObj.password, passform.data['oldpass'])
				'''Old password matches'''
				if authenticated_user:
					userObj.password = bcrypt.generate_password_hash(passform.data['newpass']).decode('UTF-8')
					try:
						'''Change password'''
						db.session.commit()
						flash('Password changed successfully!','success')
						return redirect(url_for('profile'))
					except IntegrityError as e:
						'''Error'''
						print(e)
				else:
					'''Old password does not match'''
					flash('Old password does not match','warning')

				return redirect(url_for('profile'))

			if 'chg_name' in request.form and nameform.validate_on_submit():
			
				userObj.name = nameform.data['newname']
				try:
					'''Change name'''
					db.session.commit()
					flash('Name changed successfully!','success')
					session['NAME'] = nameform.data['newname']
					return redirect(url_for('profile'))
				except IntegrityError as e:
					'''Error'''
					flash(e)

				return redirect(url_for('profile'))
		
			return render_template('profile.html', name=name, bio=bio, works_at=works_at, title=name + '\'s Page', picture=picture, passform=passform, nameform=nameform, uploadImageForm=uploadImageForm, changeworksatform=changeworksatform, changebioform=changebioform, save_icon=save_icon, edit_icon=edit_icon)
			
		else:
			flash('An error has occurred; please sign in again','secondary')
			session.pop('USER', None)
			session.pop('NAME', None)
			return redirect(url_for('login'))

	else:
		return redirect(url_for('login'))


def stereo_to_mono(audio_file_name):
    sound = AudioSegment.from_wav(audio_file_name)
    sound = sound.set_channels(1)
    sound.export(audio_file_name, format="wav")


def frame_rate_channel(audio_file_name):
    with wave.open(audio_file_name, "rb") as wave_file:
        frame_rate = wave_file.getframerate()
        channels = wave_file.getnchannels()
        return frame_rate, channels


def convert(filepath, filename):
    try:

        '''Convert speech to text'''
        frame_rate, channels = frame_rate_channel(filepath)

        if channels > 1:
            stereo_to_mono(filepath)

        '''Upload file to Google Cloud'''
        storage_client = storage.Client()

        bucket = storage_client.get_bucket('s2t-audio-bucket')
        blob = bucket.blob(filename)
        blob.upload_from_filename(filepath)

        gcs_uri = 'gs://s2t-audio-bucket/' + filename
        transcript = ''

        client = speech.SpeechClient()
        audio = types.RecognitionAudio(uri=gcs_uri)

        config = types.RecognitionConfig(
            encoding=enums.RecognitionConfig.AudioEncoding.LINEAR16, sample_rate_hertz=frame_rate, language_code='en-US')

        ''' Detects speech in the audio file '''
        operation = client.long_running_recognize(config, audio)
        response = operation.result(timeout=10000)

        for result in response.results:
            transcript += result.alternatives[0].transcript

        '''Delete files from Google Cloud'''
        blob.delete()

        return transcript

    except Exception as e:
        print(e)
        return '%unrecognised%'


@S2T.route('/transcribe', methods=['GET', 'POST'])
def transcribe():

    transcribeForm = TranscribeForm()
    if transcribeForm.validate_on_submit():
        '''Check if post request has file'''
        file = transcribeForm.upload.data
        if file.filename == '':
            flash('Please select a file','secondary')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(
            S2T.root_path, S2T.config['TEMP_FOLDER'], filename)

        try:
            file.save(filepath)
        except:
            flash('Unable to upload file','warning')
            return redirect(request.url)

        transcription = convert(filepath, filename)
        if transcription == '%unrecognised%':
            transcriptForm = TranscriptForm()
            flash('Unable to transcript audio!','warning')
        else:
            transcriptForm = TranscriptForm(
                formdata=MultiDict({'transcript': transcription}))
            flash('Audio Transcribed!','success')

            '''Remove file from temp folder'''
            os.remove(filepath)

        if session.get('USER') is None:
            return render_template('transcribe.html', title='Transcribe', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
        else:
            return render_template('transcribe.html', title='Transcribe',transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))

    '''Check if transcript has previously written data'''
    if request.method == 'GET':

        transcriptFormName = session.get('transcriptFormName', None)
        transcriptFormNameErr = session.get('transcriptFormNameErr', None)
        transcriptFormTrans = session.get('transcriptFormTrans', None)

        if (transcriptFormTrans is not None) or (transcriptFormNameErr is not None) or (transcriptFormName is not None):
            transcriptForm = TranscriptForm(formdata=MultiDict({'name': transcriptFormName, 'transcript': transcriptFormTrans}))
            transcriptForm.name.errors = transcriptFormNameErr

            session.pop('transcriptFormName')
            session.pop('transcriptFormNameErr')
            session.pop('transcriptFormTrans')
        else:
            transcriptForm = TranscriptForm()
    else:
        transcriptForm = TranscriptForm()

    if session.get('USER') is None:
        return render_template('transcribe.html', title='Transcribe', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
    else:
        return render_template('transcribe.html', title='Transcribe', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))


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
				flash('There is already a transcript with the same name!','warning')

				session['transcriptFormName'] = transcriptForm.name.data
				session['transcriptFormNameErr'] = transcriptForm.name.errors
				session['transcriptFormTrans'] = transcriptForm.transcript.data

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

				flash('File saved successfully!','success')

		except:
			flash('An error has occured; the transcript cannot be saved!','danger')

			session['transcriptFormName'] = transcriptForm.name.data
			session['transcriptFormNameErr'] = transcriptForm.name.errors
			session['transcriptFormTrans'] = transcriptForm.transcript.data

			return redirect(url_for('transcribe'))


	session['transcriptFormName'] = transcriptForm.name.data
	session['transcriptFormNameErr'] = transcriptForm.name.errors
	session['transcriptFormTrans'] = transcriptForm.transcript.data

	return redirect(url_for('transcribe'))


def getUPerm(filename, owner, user):
	perm = 'NS'
	try:
		'''Check if transcript is owned by user'''
		if owner == user:
			perm = 'RW'
		else:
			'''Check if shared with user directly'''
			uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user).first()
			if uShare:
				perm = uShare.permission
			else:
				'''Check if shared with user's group'''
				gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner).all()
				for gs in gShare:
					'''Check if user is in any group'''
					uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
					if uGrp:
						'''Check for any special permissions under the group'''
						gsd = Group_share_details.query.filter_by(gst_id=gs.share_id, username=user).first()
						if gsd:
							'''Use highest permission'''
							if gsd.permission == 'RW':
								perm = 'RW'
							elif gsd.permission == 'RO':
								if perm != 'RW':
									perm = 'RO'
							else:
								if (perm != 'RO') or (perm != 'RW'):
									perm = 'NS'
						else:
							'''Use group permission'''
							perm = gs.permission
		return perm
	except IntegrityError as e:
		print(e)
		return perm
	
	

@S2T.route('/view/<string:owner>/<string:filename>', methods=['GET'])
def view(owner, filename):
	transcriptForm = TranscriptForm()

	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')
		filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)

		shared = False
		
		uPerm = getUPerm(filename, owner, user)
		
		if (uPerm == 'RO') or (uPerm == 'RW'):
			shared = True


		if shared == False:
			flash('Transcript is not shared with you!','warning')
			return redirect(url_for('list_transcripts'))

		'''Populate transcript text area with contents'''
		try:
			with open(os.path.join(filepath, filename), 'r') as f:
				transcription = f.read()
				transcriptForm = TranscriptForm(formdata=MultiDict({'transcript': transcription, 'name': filename}))
		except IntegrityError as e:
			print(e)
			flash('Unable to read file!','warning')
			return redirect(url_for('list_transcripts'))

		return render_template('view.html', title='View', transcriptForm=transcriptForm, filename=filename)

	else:
		return redirect(url_for('login'))


@S2T.route('/download/<string:owner>/<string:filename>', methods=['GET'])
def download(owner, filename):
	'''Check if logged in'''
	if not session.get('USER') is None:
		user = session.get('USER')

		try:
			shared = False
			
			uPerm = getUPerm(filename, owner, user)
			if (uPerm == 'RO') or (uPerm == 'RW'):
				shared = True
			
			if shared:
				transObj = Transcripts.query.filter_by(name=filename, username=owner).first()
				if transObj:
					filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)
					return send_from_directory(directory=filepath, filename=filename)
				else:
					flash('File could not be found on server!','danger')
					return redirect(url_for('profile'))
			else:
				flash('Transcript is not shared with you!','warning')
				return redirect(url_for('list_transcripts'))
		except:
			flash('File could not be found on server!','danger')
			return redirect(url_for('profile'))

	else:
		return redirect(url_for('login'))


@S2T.route('/delete/<string:owner>/<string:filename>', methods=['GET'])
def delete(owner, filename):
	'''Check if logged in'''
	if not session.get('USER') is None:
		user = session.get('USER')

		try:

			shared = False

			uPerm = getUPerm(filename, owner, user)
			if uPerm == 'RW':
				shared = True


			if shared:

				'''Remove all share records of transcript'''
				uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner).all()
				for u in uShare:
					db.session.delete(u)
					db.session.commit()

				gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner).all()
				for g in gShare:
					'''Check for special permissions given for transcript'''
					gsdShare = Group_share_details.query.filter_by(gst_id=g.share_id).all()
					for gsd in gsdShare:
						db.session.delete(gsd)
						db.session.commit()
					
					db.session.delete(g)
					db.session.commit()
				

				transObj = Transcripts.query.filter_by(name=filename, username=owner).first()
				if transObj:
					filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)

					'''Remove file from database'''
					db.session.delete(transObj)
					db.session.commit()

					'''Remove file from filesystem'''
					os.remove(os.path.join(filepath, filename))
					flash('File successfully deleted!','success')

				else:
					flash('File cannot be found on server!','danger')
			else:
				flash('Transcript is not shared with you!','warning')
				return redirect(url_for('list_transcripts'))

		except IntegrityError as e:
			print(e)
			flash('File cannot be found on server!','danger')

	else:
		return redirect(url_for('login'))

	return redirect(url_for('list_transcripts'))


@S2T.route('/edit/<string:owner>/<string:old_filename>', methods=['GET', 'POST'])
def edit(owner, old_filename):

	transcriptForm = TranscriptForm()

	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')
		filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)

		'''Check if '''
		shared = False
		# try:

			# '''Check if transcript is owned by user'''
			# if owner == user:
				# shared = True
			# else:
				# '''Check if shared with user directly'''
				# uShare = Shared_transcripts.query.filter_by(name=old_filename, owner=owner, username=user, permission='RW').first()
				# if uShare:
					# shared = True
				# else:
					# '''Check is shared with user's group'''
					# gShare = Group_shared_transcripts.query.filter_by(name=old_filename, owner=owner, permission='RW').all()
					# for gs in gShare:
						# '''Check if user is in any group'''
						# uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
						# if uGrp:
							# shared = True
							# break
							
		uPerm = getUPerm(old_filename, owner, user)
		if uPerm == 'RW':
			shared = True

		# except IntegrityError as e:
			# print(e)
			# flash('Transcript is not shared with you!','warning')
			# return redirect(url_for('list_transcripts'))

		if shared == False:
			flash('Transcript is not shared with you!','warning')
			return redirect(url_for('list_transcripts'))

		if transcriptForm.validate_on_submit():

			'''Override current file with new contents'''
			try:
				os.remove(os.path.join(filepath, old_filename))

				save_text = open(os.path.join(filepath, transcriptForm.data['name']), 'w')
				save_text.write(transcriptForm.data['transcript'])
				save_text.close()

				flash('File Edited!','success')
				return redirect(url_for('list_transcripts'))

			except IntegrityError as e:
				print(e)
				flash('Unable to save file!','warning')
				return redirect(url_for('list_transcripts'))
		else:
			print(transcriptForm.errors)

		'''Populate transcript text area with contents'''
		try:
			with open(os.path.join(filepath, old_filename), 'r') as f:
				transcription = f.read()
				transcriptForm = TranscriptForm(formdata=MultiDict({'transcript': transcription, 'name': old_filename}))
		except IntegrityError as e:
			print(e)
			flash('Unable to read file!','warning')
			return redirect(url_for('list_transcripts'))

		return render_template('edit.html', title='Edit', transcriptForm=transcriptForm, owner=owner, old_filename=old_filename)

	else:
		return redirect(url_for('login'))

def getGrpOwn(group_id):
	try:
		'''Get all owners of group'''
		ownGrpObj = Group_roles.query.filter((Group_roles.group_id==group_id) & (Group_roles.role=='owner')).all()
		uOwnStr = ""

		for og in ownGrpObj:
			'''Get user object of each leader'''
			userObj = User.query.filter_by(username=og.username).first()
			if uOwnStr == '':
				uOwnStr = userObj.name
			else:
				uOwnStr += ", " + userObj.name

		return uOwnStr

	except Exception as e:
		print(e)
		return ""

def getGrpLead(group_id):
	try:
		'''Get all leaders of group'''
		leadGrpObj = Group_roles.query.filter((Group_roles.group_id==group_id) & (Group_roles.role=='leader')).all()
		uLeadStr = ""

		for lg in leadGrpObj:
			'''Get user object of each leader'''
			userObj = User.query.filter_by(username=lg.username).first()
			if uLeadStr == '':
				uLeadStr = userObj.name
			else:
				uLeadStr += ", " + userObj.name

		return uLeadStr

	except Exception as e:
		print(e)
		return ""

def getGrpMem(group_id):
	try:
		'''Get all members of group'''
		memGrpObj = Group_roles.query.filter((Group_roles.group_id==group_id) & (Group_roles.role=='member')).all()
		uMemStr = ""

		for mg in memGrpObj:
			'''Get user object of each member'''
			userObj = User.query.filter_by(username=mg.username).first()
			if uMemStr == '':
				uMemStr = userObj.name
			else:
				uMemStr += ", " + userObj.name

		return uMemStr

	except Exception as e:
		print(e)
		return ""

@S2T.route('/groups', methods=['GET', 'POST'])
def groups():
	groupform = GroupForm()

	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')

		'''Check whether user is owner'''
		isOwner = {}
		grpsTable = []

		names = {}

		'''Store all 3 types members for each grp'''
		grpsOwn = {}
		grpsMem = {}
		grpsLead = {}

		try:
			'''Get all groups user is in'''
			grpsObj = Group_roles.query.filter_by(username=user).all()

			for grp in grpsObj:
				'''check if role of user in grp is owner'''
				if grp.role == 'owner':
					isOwner[grp.group_id] = True
				else:
					isOwner[grp.group_id] = False

				grpObj = Groups.query.filter_by(group_id=grp.group_id).first()
				grpsTable.append(grpObj)

				grpsOwn[grp.group_id] = getGrpOwn(grp.group_id)
				grpsLead[grp.group_id] = getGrpLead(grp.group_id)
				grpsMem[grp.group_id] = getGrpMem(grp.group_id)

				userObj = User.query.filter_by(username=grpObj.username).first()
				names[grpObj.username] = userObj.name

		except IntegrityError as e:
			print(e)
			flash('Unable to display groups!','warning')

		'''If add new group form submitted'''
		if groupform.validate_on_submit():
			try:
				'''Check if there is already a group with the same name'''
				existing_grp = Groups.query.filter_by(group_name=groupform.data['grpname'], username=user).first()
				if existing_grp:
					flash('You already have a group with that name!','warning')
				else:
					new_grp = Groups(groupform.data['grpname'], user)
					db.session.add(new_grp)
					db.session.commit()

					'''Get grp id'''
					grpObj = Groups.query.filter_by(group_name=groupform.data['grpname'], username=user).first()
					grpId = grpObj.group_id

					'''Add new group owner role'''
					new_role = Group_roles(grpId, user, 'owner')
					db.session.add(new_role)
					db.session.commit()

					flash('Group successfully created!','success')
					return redirect(url_for('groups'))

			except IntegrityError as e:
				print(e)
				flash('Unable to create new group!','danger')

		return render_template('groups.html', title='Groups', groupform=groupform, names=names, isOwner=isOwner, grpsTable=grpsTable, grpsOwn=grpsOwn, grpsLead=grpsLead, grpsMem=grpsMem)

	else:
		return redirect(url_for('login'))

@S2T.route('/delete_group/<int:group_id>', methods=['GET'])
def delete_group(group_id):
	if not session.get('USER') is None:

		user = session.get('USER')

		'''Check is user is authorised to delete group'''
		try:
			grpRole = Group_roles.query.filter_by(username=user, group_id=group_id).first()
			if grpRole.role == 'owner':
				'''Delete all user role records in group_roles'''
				db.session.query(Group_roles).filter_by(group_id=group_id).delete()
				db.session.commit()

				'''Delete all Group_shared_transcripts records'''
				db.session.query(Group_shared_transcripts).filter_by(group_id=group_id).delete()
				db.session.commit()

				'''Delete group entry'''
				db.session.query(Groups).filter_by(group_id=group_id).delete()
				db.session.commit()

				flash('Group successfully deleted','success')

			else:
				flash('Not authorised','danger')

		except IntegrityError as e:
			print(e)
			flash('Unable to delete group!','warning')

		return redirect(url_for('groups'))

	else:
		return redirect(url_for('login'))


'''Return list of all users'''
@S2T.route('/all_users', methods=['GET'])
def user_dict():
	list_user = []

	if not session.get('USER') is None:
		try:
			res = User.query.filter(User.username != session.get('USER')).all()
			list_user = [r.as_dict() for r in res]
		except:
			return jsonify('Unable to liist users')

	return jsonify(list_user)


'''Return list of searched users'''
@S2T.route('/search_users/<string:owner>/<string:filename>', methods=['GET'])
def search_users(owner, filename):
	list_users = []

	if not session.get('USER') is None:
		try:
			suObj = Shared_transcripts.query.filter_by(name=filename, owner=owner).all()
			for su in suObj:
				userObj = User.query.filter_by(username=su.username).first()
				list_users.append({'user_perm':su.permission, 'username': su.username, 'name':userObj.name})
		except IntegrityError as e:
			print(e)
			return jsonify('Unable to list users')

	return jsonify(list_users)



'''Return list of searched groups'''
@S2T.route('/search_groups/<string:owner>/<string:filename>', methods=['GET'])
def search_groups(owner, filename):
	list_grps = []

	if not session.get('USER') is None:
		try:
			res = Group_roles.query.filter_by(username=session.get('USER')).all()
			
			for r in res:
				grpOwn = getGrpOwn(r.group_id)
				grpLead = getGrpLead(r.group_id)
				grpMem = getGrpMem(r.group_id)

				grpObj = Groups.query.filter_by(group_id=r.group_id).first()

				grpShareObj = Group_shared_transcripts.query.filter_by(group_id=r.group_id, name=filename, owner=owner).first()
				grpPerm = 'Not Shared'
				allowShare = 'N'
				if grpShareObj:
					grpPerm = grpShareObj.permission
					allowShare = grpShareObj.allow_share
				
				list_grps.append({'group_perm':grpPerm, 'allow_share':allowShare, 'group_id':r.group_id, 'group_name':grpObj.group_name, 'username':grpObj.username, 'owners':grpOwn, 'leaders':grpLead, 'members':grpMem})

		except IntegrityError as e:
			print(e)
			return jsonify('Unable to list groups')

	return jsonify(list_grps)

'''Return list of group members'''
@S2T.route('/get_group_mems', methods=['POST'])
def get_group_mems():
	group_id = request.form.get('group_id')
	
	'''Transcript information'''
	filename = request.form.get('filename')
	owner = request.form.get('owner')
	
	list_mems = []
	
	if not session.get('USER') is None:
		try:
			grObj = Group_roles.query.filter_by(group_id=group_id).all()
			for gr in grObj:
				'''Get name of user'''
				userObj = User.query.filter_by(username=gr.username).first()
				
				'''Get current special permission (if any)'''
				perm = 'GP'
				
				'''Get transcript ID (if shared)'''
				gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gr.group_id).first()
				if gst:
					'''Transcript is shared; might have special permissions'''
					gsd = Group_share_details.query.filter_by(gst_id=gst.share_id, username=gr.username).first()
					if gsd:
						'''User has special permissions'''
						perm = gsd.permission
				
				
				list_mems.append({'username':gr.username, 'name': userObj.name, 'role':gr.role, 'perm':perm})
				
		except IntegrityError as e:
			print(e)
			return jsonify('Unable to list members')
		
	return jsonify(list_mems)

@S2T.route('/share/<string:owner>/<string:filename>', methods=['GET', 'POST'])
def share(owner, filename):

	'''Check if logged in'''
	if not session.get('USER') is None:

		'''Get list of users already shared'''
		shared_usernames = []
		shared_names = {}
		try:
			sharedObj = Shared_transcripts.query.filter_by(owner=owner, name=filename).all()
			for su in sharedObj:
				shared_usernames.append(su.username)

				userObj = User.query.filter_by(username=su.username).first()
				shared_names[su.username] = userObj.name

		except IntegrityError as e:
			print(e)

		return render_template('share_transcript.html', title='Sharing transcript', owner=owner, filename=filename, shared_names=shared_names, shared_usernames=shared_usernames)

	else:
		return redirect(url_for('login'))

@S2T.route('/share_users', methods=['POST'])
def share_users():

	'''Check if logged in'''
	if not session.get('USER') is None:

		owner = request.form.get('owner')
		filename = request.form.get('filename')
		share_users = request.form.getlist('share_users[]')
		permissions = request.form.getlist('permissions[]')

		'''Add users in shared_transcripts table'''
		try:
			for idx, shared_user in enumerate(share_users):

				new_share = Shared_transcripts(filename, owner, shared_user, permissions[idx])
				db.session.add(new_share)
				db.session.commit()

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to share transcript")


		return jsonify("Transcript successfully shared")

	else:
		return jsonify("not logged in")


@S2T.route('/edit_user_share', methods=['POST'])
def edit_user_share():

	'''Check if logged in'''
	if not session.get('USER') is None:

		owner = request.form.get('owner')
		filename = request.form.get('filename')
		editUsers = request.form.getlist('editUsers[]')
		permissions = request.form.getlist('permissions[]')

		'''Add users in shared_transcripts table'''
		try:
			for idx, user in enumerate(editUsers):

				'''Check if user is not shared (may need to delete from db)'''
				if permissions[idx] == 'NS':
					'''Check if there is a record in db'''
					ust = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user).delete()
					db.session.commit()

				else:
					'''Need to modify or add record'''
					ust = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user).first()
					if ust:
						ust.permission = permissions[idx]
					else:
						ust = Shared_transcripts(filename, owner, user, permissions[idx])


					db.session.add(ust)
					db.session.commit()


			return jsonify("Transcript successfully shared")

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to share transcript")

	else:
		return jsonify("not logged in")


@S2T.route('/share_groups', methods=['POST'])
def share_groups():

	'''Check if logged in'''
	if not session.get('USER') is None:

		owner = request.form.get('owner')
		filename = request.form.get('filename')
		group_ids = request.form.getlist('gid[]')
		permissions = request.form.getlist('permissions[]')
		allow_share = request.form.getlist('allow_share[]')
		
		member_dets = request.form.getlist('member_dets[]')
		members = {}
		'''Organise member permission details into specific groups'''
		for mdJSON in member_dets:
			'''Parse JSON'''
			md = json.loads(mdJSON)
			
			md_gid = md.get('gid')
			md_user = md.get('username')
			md_perm = md.get('permission')
			
			if members.get(md_gid) is None:
				newDict = {}
				'''print(type(newDict))'''
				newDict[md_user] = md_perm
				members[md_gid] = newDict
			else:
				members[md_gid][md_user] = md_perm
		
		
		'''Add groups in shared_transcripts table'''
		try:
			for idx, gid in enumerate(group_ids):

				'''Check if gid is not shared (may need to delete from db)'''
				if permissions[idx] == 'NS':
					
					'''Check if there is a record in db'''
					gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).first()
					if gst:
						
						'''Remove any special permissions given in the db'''
						gsd = Group_share_details.query.filter_by(gst_id=gst.share_id).delete()
						
						db.session.delete(gst)
						db.session.commit()
					
				else:
					'''Need to modify or add record'''
					
					'''Check if there is a record in db'''
					gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).first()
					
					if gst:
						'''Record exists'''
						'''Edit permission'''
						gst.permission = permissions[idx]
						
						'''Edit allow_share'''
						gst.allow_share = allow_share[idx]
						
						db.session.add(gst)
						db.session.commit()
						
						'''Check all special permissions for users'''
						gsdObj = Group_share_details.query.filter_by(gst_id=gst.share_id).all()
						
						'''Extract dict of members and permissions'''
						memPerm = members.get(gid)
						
						for gsd in gsdObj:
							'''Traverse dict to look for respective username (if dict is not empty)'''
							
							if memPerm is None:
								'''No special permissions; remove all related entries'''
								db.session.delete(gsd)
								db.session.commit()
							else:
								'''There are special permissions'''
								if memPerm.get(gsd.username) is None:
									'''Need to remove record from db'''
									db.session.delete(gsd)
									db.session.commit()
								else:
									'''Need to update permissions'''
									gsd.permission = memPerm.get(gsd.username)
									db.session.add(gsd)
									db.session.commit()
									
									'''Remove user from dictionary'''
									memPerm.pop(gsd.username)
									
						
						'''For any usernames left in dictionary, need to add them into the db'''
						if not memPerm is None:
							memPermKeys = memPerm.keys()
							for mpk in memPermKeys:
								'''Get corresponding permission'''
								corrPerm = memPerm.get(mpk)
								
								'''Add new record into db'''
								new_gsd = Group_share_details(gst.share_id, mpk, corrPerm)
								db.session.add(new_gsd)
								db.session.commit()
								
					else:
						'''Create new record first'''
						new_gst = Group_shared_transcripts(filename, owner, gid, permissions[idx], allow_share[idx])
						db.session.add(new_gst)
						db.session.commit()
						
						gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).first()
						
						'''Update special member permissions (if any)'''
						memPerm = members.get(gid)
						
						if not memPerm is None:
						
							memPermKeys = memPerm.keys()
							for mpk in memPermKeys:
								'''Get corresponding permission'''
								corrPerm = memPerm.get(mpk)
								
								'''Add new record into db'''
								new_gsd = Group_share_details(gst.share_id, mpk, corrPerm)
								db.session.add(new_gsd)
								db.session.commit()
						
					'''
					gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).first()
					if gst:
						gst.permission = permissions[idx]
					else:
						gst = Group_shared_transcripts(filename, owner, gid, permissions[idx], 'N')
						
					db.session.add(gst)
					db.session.commit()
					'''

			return jsonify("Transcript successfully shared")

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to share transcript")

	else:
		return jsonify("not logged in")

@S2T.route('/get_shared_users', methods=['POST'])
def get_shared_users():
	'''Check if logged in'''
	if not session.get('USER') is None:

		suList = []

		owner = request.form.get('owner')
		filename = request.form.get('filename')

		stObj = Shared_transcripts.query.filter_by(name=filename, owner=owner).all()
		for st in stObj:
			suList.append({'username':st.username})

		return jsonify(suList)

	else:
		return jsonify("not logged in")


@S2T.route('/get_mem/<int:group_id>', methods=['GET'])
def get_mem(group_id):
	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')

		try:
			'''Get list of group members (for preventing duplicate entries)'''
			allMemObj = Group_roles.query.filter_by(group_id=group_id).all()
			memList = []
			for am in allMemObj:
				userObj = User.query.filter_by(username=am.username).first()
				memList.append({'username':am.username, 'name':userObj.name, 'role':am.role})

			return jsonify(memList)

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to get list")

	else:
		return jsonify("not logged in")


@S2T.route('/members/<int:group_id>', methods=['GET'])
def members(group_id):

	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')

		try:
			'''Get group object'''
			grpObj = Groups.query.filter_by(group_id=group_id).first()

			'''Get authorization of user'''
			grObj = Group_roles.query.filter_by(group_id=group_id, username=user).first()
			if grObj:
				role = grObj.role

				grpOwn = getGrpOwn(group_id)
				grpLead = getGrpLead(group_id)
				grpMem = getGrpMem(group_id)

				if role == 'leader' or role == 'owner':
					'''Get all grp member names and roles for editing'''
					grpRoles = Group_roles.query.filter_by(group_id=group_id).all()
					allGrpMem = []
					for gr in grpRoles:
						uName = User.query.filter_by(username=gr.username).first()
						name = uName.name

						allGrpMem.append({'username':gr.username, 'name':name, 'role':gr.role})

					return render_template('members.html', title='Members', allGrpMem=allGrpMem, grpOwn=grpOwn, grpLead=grpLead, grpMem=grpMem, grpObj=grpObj, role=role)
				else:
					return render_template('members.html', title='Members', grpOwn=grpOwn, grpLead=grpLead, grpMem=grpMem, grpObj=grpObj, role=role)

			else:
				flash('You are a member of this group!','secondary')
				return redirect(url_for('groups'))

		except Exception as e:
			print(e)
			return redirect(url_for('groups'))

	else:
		return redirect(url_for('login'))

@S2T.route('/add_members', methods=['POST'])
def add_members():
	'''Check if logged in'''
	if not session.get('USER') is None:

		grpId = request.form.get('grpId')
		add_members = request.form.getlist('add_members[]')
		roles = request.form.getlist('roles[]')

		try:
			'''Add users into group (if user is not already in group)'''
			for idx, addMem in enumerate(add_members):
				newRole = Group_roles(grpId, addMem, roles[idx])
				db.session.add(newRole)
				db.session.commit()

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to add member")


		return jsonify("Members successfully added")

	else:
		return jsonify("not logged in")


@S2T.route('/edit_members', methods=['POST'])
def edit_members():
	'''Check if logged in'''
	if not session.get('USER') is None:

		editMembers = request.form.getlist('editMembers[]')
		roles = request.form.getlist('roles[]')
		grpId = request.form.get('grpId')
		deleteMembers = request.form.getlist('deleteMembers[]')

		try:
			'''Delete Members'''
			for delMem in deleteMembers:
				db.session.query(Group_roles).filter_by(group_id=grpId, username=delMem).delete()
				db.session.commit()

			'''Change member roles'''
			for idx, edMem in enumerate(editMembers):
				edMemObj = Group_roles.query.filter_by(group_id=grpId, username=edMem).first()
				edMemObj.role = roles[idx]
				db.session.add(edMemObj)
				db.session.commit()

			return jsonify('Members successfully changed')

		except IntegrityError as e:
			print(e)
			return jsonify('Unable to edit members')

	else:
		return jsonify('not logged in')


@S2T.route('/list_transcripts', methods=['GET'])
def list_transcripts():
	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')
		myTranscripts = []
		
		sharedTrans = []
		
		try:
			'''Get user's transcripts'''
			transObj = Transcripts.query.filter_by(username=user).all()

			for tran in transObj:
				myTranscripts.append(tran)

			'''Get transcripts shared with user'''

			stuObj = Shared_transcripts.query.filter_by(username=user).all()
			for stu in stuObj:
				
				swArr = []
				swArr.append("You")
				
				sharedTrans.append({'name':stu.name, 'owner':stu.owner, 'sharedWith':swArr, 'permission':stu.permission, 'allow_share':'N', 'dup':'false'})
			
			

			'''Get groups the user is in'''
			grpObj = Group_roles.query.filter_by(username=user).all()
			
			'''List to store groups with NS permission applied to user'''
			NSList = {}
			
			for grp in grpObj:
				
				'''Get transcripts shared with group (make sure no duplicate transcripts)'''
				stgObj = Group_shared_transcripts.query.filter_by(group_id=grp.group_id).all()
				for stg in stgObj:
					owner = False

					'''Check if duplicated in myTranscripts'''
					for t in myTranscripts:
						if t.name == stg.name and t.username == stg.owner:
							owner = True
							break
					
					
					if (owner == False):
						'''Check if there is already another share with another group that user is in'''
						oShare = False
						for st in sharedTrans:
							if st.get('name') == stg.name and st.get('owner') == stg.owner:
								'''There is another share'''
								oShare = True
								
								'''Check whether group allows sharing by owners/leaders'''
								if (stg.allow_share == 'Y') and (st.get('allow_share') != 'Y'):
									'''Check if user's role is leader/owner'''
									checkRole = Group_roles.query.filter_by(group_id=grp.group_id, username=user).first()
									
									if (checkRole.role == 'leader') or (checkRole.role == 'owner'):
										'''Override current perm'''
										st['allow_share'] = 'Y'
								
								
								
								'''Update shared with and permissions'''
								if st.get('dup') == 'false':
								
									if st.get('permission') == "RO":
										newText = st['sharedWith'].pop() + " (Read Only)"
										st['sharedWith'].append(newText)
									elif st.get('permission') == "RW":
										newText = st['sharedWith'].pop() + " (Read & Write)"
										st['sharedWith'].append(newText)							
									
									st['dup'] = 'true'
									
								
								
								'''Query for group name'''
								g = Groups.query.filter_by(group_id=grp.group_id).first()
								
								'''Need to check special permissions (if any)'''
								gsd = Group_share_details.query.filter_by(gst_id=stg.share_id, username=user).first()
								
								if gsd:
									'''If special permissions are higher than current, use special'''
									if (gsd.permission == "RW"):
										st['sharedWith'].append(g.group_name + " (Read & Write)")
										st['permission'] = "RW"
										
									elif (gsd.permission == "RO"):
										'''No need to change permissions, either current is alrdy RW or RO'''
										st['sharedWith'].append(g.group_name + " (Read Only)")
									
									else:
										'''Not shared but overrided by other group share'''
										st['sharedWith'].append(g.group_name + " (Excluded Sharing)")
										
										
								else:
									'''No special permissions for user; use group permissions if higher'''
									if (stg.permission == "RW"):
										st['sharedWith'].append(g.group_name + " (Read & Write)")
										st['permission'] = "RW"
										
									elif (stg.permission == "RO"):
										st['sharedWith'].append(g.group_name + " (Read Only)")
									else:
										st['sharedWith'].append(g.group_name + " (Excluded Sharing)")
									
								
								'''Break out of loop checking'''
								break
								
						if oShare == False:
							'''No other shares'''
							'''Create new entry in sharedTrans'''
							
							'''Check whether group allows sharing by owners/leaders'''
							allowShare = 'N'
							if stg.allow_share == 'Y':
								'''Check if user's role is leader/owner'''
								checkRole = Group_roles.query.filter_by(group_id=grp.group_id, username=user).first()
								
								if (checkRole.role == 'leader') or (checkRole.role == 'owner'):
									'''Override current perm'''
									allowShare = 'Y'
							
							
							'''Need to check special permissions'''
							gsd = Group_share_details.query.filter_by(gst_id=stg.share_id, username=user).first()
							
							'''Query for group name'''
							g = Groups.query.filter_by(group_id=grp.group_id).first()
							
							
							swText = ""
							swArr = []
							
							'''Check NSList for previous group not shared'''
							NSLI = stg.name + stg.owner
							NS_Append = False
							
							if not NSList.get(NSLI) is None:
								NS_Append = True
								'''Update swText with previous group's name'''
								swText += NSList.get(NSLI) + " (Excluded Sharing)"
								swArr.append(swText)
							
							swText = g.group_name
							
							if gsd:
								print(gsd.permission)
								'''If special permissions are higher than group, use special'''
								if (gsd.permission == "RW"):
									if NS_Append:
										swText += ' (Read & Write)'
									
									swArr.append(swText)
										
									sharedTrans.append({'name':stg.name, 'owner':stg.owner, 'sharedWith':swArr, 'permission':gsd.permission, 'allow_share':allowShare, 'dup':'false'})
									
								elif (gsd.permission == "RO"):
									if NS_Append:
										swText += ' (Read Only)'
									
									swArr.append(swText)
										
									sharedTrans.append({'name':stg.name, 'owner':stg.owner, 'sharedWith':swArr, 'permission':gsd.permission, 'allow_share':allowShare, 'dup':'false'})
								else:
									'''If not shared, don't add to transcripts'''
									'''Need to update record of not shared with group name'''
									NSListInd = stg.name + stg.owner
									NSList[NSListInd] = g.group_name
								
							else:
								'''No special permissions for user; use group permissions if higher'''
								if (stg.permission == "RW"):
									if NS_Append:
										swText += ' (Read & Write)'
									
									swArr.append(swText)
									
									sharedTrans.append({'name':stg.name, 'owner':stg.owner, 'sharedWith':swArr, 'permission':stg.permission, 'allow_share':allowShare, 'dup':'false'})
									
								elif (stg.permission == "RO"):
									
									if NS_Append:
										swText += ' (Read Only)'
									
									swArr.append(swText)
									
									sharedTrans.append({'name':stg.name, 'owner':stg.owner, 'sharedWith':swArr, 'permission':stg.permission, 'allow_share':allowShare, 'dup':'false'})
								else:
									'''If not shared, don't add to transcripts'''
									'''Need to update record of not shared with group name'''
									NSListInd = stg.name + stg.owner
									NSList[NSListInd] = g.group_name
									
						
		except IntegrityError as e:
			print(e)
			return redirect(url_for('profile'))

		return render_template('transcripts.html', title='Transcripts', myTranscripts=myTranscripts, sharedTrans=sharedTrans)

	else:
		return redirect(url_for('login'))
