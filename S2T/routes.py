import os
from flask import render_template, flash, redirect, url_for, session, request, send_from_directory, jsonify, json
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm, TranscribeForm, TranscriptForm, GroupForm
from werkzeug.utils import secure_filename

from S2T.models import User, Transcripts, Groups, Group_roles, Shared_transcripts, Group_shared_transcripts
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

        flash('Signup successful for user {}'.format(form.username.data))
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
                return redirect(url_for('profile'))

            else:
                flash('Login unsuccessful for user {}'.format(form.username.data), 'danger')
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
                authenticated_user = bcrypt.check_password_hash(
                    userObj.password, passform.data['oldpass'])
                '''Old password matches'''
                if authenticated_user:
                    userObj.password = bcrypt.generate_password_hash(
                        passform.data['newpass']).decode('UTF-8')
                    try:
                        '''Change password'''
                        db.session.commit()
                        flash('Password changed successfully!','success')
                        return redirect(url_for('profile'))
                    except IntegrityError as e:
                        '''Error'''
                        flash(e)
                else:
                    '''Old password does not match'''
                    flash('Old password does not match','warning')
            else:
                '''No user found (unexpected)'''
                flash('An error has occurred; please sign in again','secondary')
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
                    flash('Name changed successfully!','success')
                    session['NAME'] = nameform.data['newname']
                    return redirect(url_for('profile'))
                except IntegrityError as e:
                    '''Error'''
                    flash(e)
            else:
                '''No user found (unexpected)'''
                flash('An error has occurred; please sign in again','secondary')
                session.pop('USER', None)
                session.pop('NAME', None)
                return redirect(url_for('login'))

            return redirect(url_for('profile'))

        return render_template('profile.html', name=name, title=name + '\'s Page', passform=passform, nameform=nameform, transcripts=transTable)

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
            flash('Please select a file')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(
            S2T.root_path, S2T.config['TEMP_FOLDER'], filename)

        try:
            file.save(filepath)
        except:
            flash('Unable to upload file')
            return redirect(request.url)

        transcription = convert(filepath, filename)
        if transcription == '%unrecognised%':
            transcriptForm = TranscriptForm()
            flash('Unable to transcript audio!')
        else:
            transcriptForm = TranscriptForm(
                formdata=MultiDict({'transcript': transcription}))
            flash('Audio Transcribed!')

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
				flash('There is already a transcript with the same name!')

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

				flash('File saved successfully!')

		except:
			flash('An error has occured; the transcript cannot be saved!')

			session['transcriptFormName'] = transcriptForm.name.data
			session['transcriptFormNameErr'] = transcriptForm.name.errors
			session['transcriptFormTrans'] = transcriptForm.transcript.data

			return redirect(url_for('transcribe'))


	session['transcriptFormName'] = transcriptForm.name.data
	session['transcriptFormNameErr'] = transcriptForm.name.errors
	session['transcriptFormTrans'] = transcriptForm.transcript.data

	return redirect(url_for('transcribe'))


@S2T.route('/view/<string:owner>/<string:filename>', methods=['GET'])
def view(owner, filename):
	transcriptForm = TranscriptForm()

	'''Check if logged in'''
	if not session.get('USER') is None:

		user = session.get('USER')
		filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)

		shared = False
		try:

			'''Check if transcript is owned by user'''
			if owner == user:
				shared = True
			else:
				'''Check if shared with user directly'''
				uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user, permission='RO').first()
				if uShare:
					shared = True
				else:
					'''Check is shared with user's group'''
					gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, permission='RO').all()
					for gs in gShare:
						'''Check if user is in any group'''
						uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
						if uGrp:
							shared = True
							break

		except IntegrityError as e:
			print(e)
			flash('Transcript is not shared with you!')
			return redirect(url_for('list_transcripts'))

		if shared == False:
			flash('Transcript is not shared with you!')
			return redirect(url_for('list_transcripts'))

		'''Populate transcript text area with contents'''
		try:
			with open(os.path.join(filepath, filename), 'r') as f:
				transcription = f.read()
				transcriptForm = TranscriptForm(formdata=MultiDict({'transcript': transcription, 'name': filename}))
		except IntegrityError as e:
			print(e)
			flash('Unable to read file!')
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

			'''Check if transcript is owned by user'''
			if owner == user:
				shared = True
			else:
				'''Check if shared with user directly'''
				uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user).first()
				if uShare:
					shared = True
				else:
					'''Check is shared with user's group'''
					gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner).all()
					for gs in gShare:
						'''Check if user is in any group'''
						uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
						if uGrp:
							shared = True
							break

			if shared:
				transObj = Transcripts.query.filter_by(name=filename, username=owner).first()
				if transObj:
					filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], owner)
					return send_from_directory(directory=filepath, filename=filename)
				else:
					flash('File could not be found on server!')
					return redirect(url_for('profile'))
			else:
				flash('Transcript is not shared with you!')
				return redirect(url_for('list_transcripts'))
		except:
			flash('File could not be found on server!')
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

			'''Check if transcript is owned by user'''
			if owner == user:
				shared = True
			else:
				'''Check if shared with user directly'''
				uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner, username=user, permission='RW').first()
				if uShare:
					shared = True
				else:
					'''Check is shared with user's group'''
					gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, permission='RW').all()
					for gs in gShare:
						'''Check if user is in any group'''
						uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
						if uGrp:
							shared = True
							break

			if shared:

				'''Remove all share records of transcript'''
				uShare = Shared_transcripts.query.filter_by(name=filename, owner=owner).all()
				for u in uShare:
					db.session.delete(u)
					db.session.commit()

				gShare = Group_shared_transcripts.query.filter_by(name=filename, owner=owner).all()
				for g in gShare:
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
					flash('File successfully deleted!')

				else:
					flash('File cannot be found on server!')
			else:
				flash('Transcript is not shared with you!')
				return redirect(url_for('list_transcripts'))

		except IntegrityError as e:
			print(e)
			flash('File cannot be found on server!')

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
		try:

			'''Check if transcript is owned by user'''
			if owner == user:
				shared = True
			else:
				'''Check if shared with user directly'''
				uShare = Shared_transcripts.query.filter_by(name=old_filename, owner=owner, username=user, permission='RW').first()
				if uShare:
					shared = True
				else:
					'''Check is shared with user's group'''
					gShare = Group_shared_transcripts.query.filter_by(name=old_filename, owner=owner, permission='RW').all()
					for gs in gShare:
						'''Check if user is in any group'''
						uGrp = Group_roles.query.filter_by(group_id=gs.group_id, username=user).first()
						if uGrp:
							shared = True
							break

		except IntegrityError as e:
			print(e)
			flash('Transcript is not shared with you!')
			return redirect(url_for('list_transcripts'))

		if shared == False:
			flash('Transcript is not shared with you!')
			return redirect(url_for('list_transcripts'))

		if transcriptForm.validate_on_submit():
			'''Update database with new name'''
			try:
				transObj = Transcripts.query.filter_by(name=old_filename, username=owner).first()
				transObj.name = transcriptForm.data['name']

				db.session.commit()

			except IntegrityError as e:
				print(e)
				flash('Unable to update database!')
				return redirect(url_for('list_transcripts'))

			'''Override current file with new contents'''
			try:
				os.remove(os.path.join(filepath, old_filename))

				save_text = open(os.path.join(filepath, transcriptForm.data['name']), 'w')
				save_text.write(transcriptForm.data['transcript'])
				save_text.close()

				flash('File Edited!')
				return redirect(url_for('list_transcripts'))

			except IntegrityError as e:
				print(e)
				flash('Unable to save file!')
				return redirect(url_for('list_transcripts'))

		'''Populate transcript text area with contents'''
		try:
			with open(os.path.join(filepath, old_filename), 'r') as f:
				transcription = f.read()
				transcriptForm = TranscriptForm(formdata=MultiDict({'transcript': transcription, 'name': old_filename}))
		except IntegrityError as e:
			print(e)
			flash('Unable to read file!')
			return redirect(url_for('list_transcripts'))

		return render_template('edit.html', title='Edit', transcriptForm=transcriptForm, old_filename=old_filename)

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
			flash('Unable to display groups!')

		'''If add new group form submitted'''
		if groupform.validate_on_submit():
			try:
				'''Check if there is already a group with the same name'''
				existing_grp = Groups.query.filter_by(
					group_name=groupform.data['grpname'], username=user).first()
				if existing_grp:
					flash('You already have a group with that name!')
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

					flash('Group successfully created!')
					return redirect(url_for('groups'))

			except IntegrityError as e:
				print(e)
				flash('Unable to create new group!')

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

				flash('Group successfully deleted')

			else:
				flash('Not authorised')

		except IntegrityError as e:
			print(e)
			flash('Unable to delete group!')

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
				if grpShareObj:
					grpPerm = grpShareObj.permission

				list_grps.append({'group_perm':grpPerm, 'group_id':r.group_id, 'group_name':grpObj.group_name, 'username':grpObj.username, 'owners':grpOwn, 'leaders':grpLead, 'members':grpMem})

			return jsonify(list_grps)

		except IntegrityError as e:
			print(e)
			return jsonify('Unable to list groups')

	return jsonify(list_grps)


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

@S2T.route('/share_groups', methods=['POST'])
def share_groups():

	'''Check if logged in'''
	if not session.get('USER') is None:

		owner = request.form.get('owner')
		filename = request.form.get('filename')
		group_ids = request.form.getlist('gid[]')
		permissions = request.form.getlist('permissions[]')

		'''Add groups in shared_transcripts table'''
		try:
			for idx, gid in enumerate(group_ids):

				'''Check if gid is not shared (may need to delete from db)'''
				if permissions[idx] == 'NS':
					'''Check if there is a record in db'''
					gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).delete()
					db.session.commit()

				else:
					'''Need to modify or add record'''
					gst = Group_shared_transcripts.query.filter_by(name=filename, owner=owner, group_id=gid).first()
					if gst:
						gst.permission = permissions[idx]
					else:
						gst = Group_shared_transcripts(filename, owner, gid, permissions[idx])


					db.session.add(gst)
					db.session.commit()


			return jsonify("Transcript successfully shared")

		except IntegrityError as e:
			print(e)
			return jsonify("Unable to share transcript")

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
				memList.append({'username':am.username, 'name':am.name, 'role':am.role})

			return jsonify(memList)

		except:
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
				flash('You are a member of this group!')
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
			'''Add users into group'''
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
		sharedUTrans = []
		sharedGTrans = []

		try:
			'''Get user's transcripts'''
			transObj = Transcripts.query.filter_by(username=user).all()

			for tran in transObj:
				myTranscripts.append(tran)

			'''Get transcripts shared with user'''

			stuObj = Shared_transcripts.query.filter_by(username=user).all()
			for stu in stuObj:
				sharedUTrans.append(stu)


			'''Get groups the user is in'''
			grpObj = Group_roles.query.filter_by(username=user).all()
			for grp in grpObj:
				'''Get transcripts shared with group (make sure no duplicate transcripts)'''
				stgObj = Group_shared_transcripts.query.filter_by(group_id=grp.group_id).all()
				for stg in stgObj:
					duplicate = False

					'''Check if duplicated in myTranscripts'''
					for t in myTranscripts:
						if t.name == stg.name and t.username == stg.owner:
							duplicate = True
							break

					'''Check if duplicated in sharedUTrans'''
					for t in sharedUTrans:
						if t.name == stg.name and t.owner == stg.owner:
							duplicate = True
							break

					if (duplicate == False):
						'''Get group name and group owner'''
						gObj = Groups.query.filter_by(group_id=stg.group_id).first()

						sharedGTrans.append({'name':stg.name,'owner':stg.owner,'group_id':stg.group_id,'group_name':gObj.group_name,'group_creator':gObj.username,'permission':stg.permission})
		except IntegrityError as e:
			print(e)
			return redirect(url_for('profile'))

		return render_template('transcripts.html', title='Transcripts', myTranscripts=myTranscripts, sharedUTrans=sharedUTrans, sharedGTrans=sharedGTrans)

	else:
		return redirect(url_for('login'))
