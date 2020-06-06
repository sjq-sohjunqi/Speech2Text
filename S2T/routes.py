import os
from flask import render_template, flash, redirect, url_for, session, request, send_from_directory, jsonify, json
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm, TranscribeForm, TranscriptForm, GroupForm
from werkzeug.utils import secure_filename

from S2T.models import User, Transcripts, Groups, Group_roles, Shared_transcripts
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
            authenticated_user = bcrypt.check_password_hash(
                userObj.password, form.data['password'])
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
                authenticated_user = bcrypt.check_password_hash(
                    userObj.password, passform.data['oldpass'])
                '''Old password matches'''
                if authenticated_user:
                    userObj.password = bcrypt.generate_password_hash(
                        passform.data['newpass']).decode('UTF-8')
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

        # r = sr.Recognizer()
        # file = sr.AudioFile(filepath)
        # with file as source:
        # '''Adjust for noise'''
        # r.adjust_for_ambient_noise(source, duration=0.5)

        # audio = r.record(source)

        # '''return r.recognize_google(audio)'''
        # return r.recognize_google_cloud(audio, language = 'en-US')
    # except sr.UnknownValueError as u:
        # print(u)
        # print("Google Cloud Speech Recognition could not understand audio")
    # except sr.RequestError as e:
        # print("Could not request results from Google Cloud Speech Recognition service; {0}".format(e))
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
            return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm)
        else:
            return render_template('transcribe.html', transcribeForm=transcribeForm, transcriptForm=transcriptForm, user=session.get('USER'))

    '''Check if transcript has previously written data'''
    if request.method == 'GET':

        transcriptFormName = session.get('transcriptFormName', None)
        transcriptFormNameErr = session.get('transcriptFormNameErr', None)
        transcriptFormTrans = session.get('transcriptFormTrans', None)

        if transcriptFormNameErr:
            transcriptForm = TranscriptForm(formdata=MultiDict(
                {'name': transcriptFormName, 'transcript': transcriptFormTrans}))
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
            transObj = Transcripts.query.filter_by(
                name=transcriptForm.data['name'], username=session.get('USER')).first()
            if transObj:
                flash('There is already a transcript with the same name!')
                return redirect(url_for('transcribe'))

            else:

                filepath = os.path.join(S2T.root_path, S2T.config['STORAGE_FOLDER'], session.get(
                    'USER'), transcriptForm.data['name'])
                filedir = os.path.join(
                    S2T.root_path, S2T.config['STORAGE_FOLDER'], session.get('USER'))

                '''Save new file'''
                if not os.path.exists(filedir):
                    os.mkdir(filedir)

                save_text = open(filepath, 'w')
                save_text.write(transcriptText)
                save_text.close()

                '''Update database'''
                new_transcript = Transcripts(
                    name=transcriptForm.data['name'], username=session.get('USER'))
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
            transObj = Transcripts.query.filter_by(
                name=filename, username=user).first()
            if transObj:
                filepath = os.path.join(
                    S2T.root_path, S2T.config['STORAGE_FOLDER'], user)
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
            transObj = Transcripts.query.filter_by(
                name=filename, username=user).first()
            if transObj:
                filepath = os.path.join(
                    S2T.root_path, S2T.config['STORAGE_FOLDER'], user)

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
        filepath = os.path.join(
            S2T.root_path, S2T.config['STORAGE_FOLDER'], user)

        if transcriptForm.validate_on_submit():
            '''Update database with new name'''
            try:
                transObj = Transcripts.query.filter_by(
                    name=old_filename, username=user).first()
                transObj.name = transcriptForm.data['name']

                db.session.commit()

            except:
                flash('Unable to update database!')
                return redirect(url_for('profile'))

            '''Override current file with new contents'''
            try:
                os.remove(os.path.join(filepath, old_filename))

                save_text = open(os.path.join(
                    filepath, transcriptForm.data['name']), 'w')
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
                transcriptForm = TranscriptForm(formdata=MultiDict(
                    {'transcript': transcription, 'name': old_filename}))
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

        '''Automated searching'''
        formSearch = SearchForm(request.form)

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
                    flash('Group successfully created!')

            except IntegrityError as e:
                print(e)
                flash('Unable to create new group!')

        return render_template('groups.html', groupform=groupform, grpsTable=grpsTable, formSearch=formSearch)

    else:
        return redirect(url_for('login'))


'''Return list of all users except array given'''


@S2T.route('/all_users', methods=['GET'])
def user_dict():
    list_user = []

    if not session.get('USER') is None:
        res = User.query.filter(User.username != session.get('USER')).all()
        list_user = [r.as_dict() for r in res]

    return jsonify(list_user)


'''Return list of all groups except array given'''


def group_dict(exempt):
    res = Groups.query.all()
    list_grps = []

    for r in res:
        if len(exempt) != 0:
            ctr = 0
            for e in exempt:
                if e == r.group_name:
                    ctr = ctr + 1

            if ctr == 0:
                list_grps.append(r.as_dict())
        else:
            list_grps.append(r.as_dict())

    return jsonify(list_grps)


@S2T.route('/share/<string:owner>/<string:filename>', methods=['GET', 'POST'])
def share(owner, filename):
	
	'''Check if logged in'''
	if not session.get('USER') is None:
		return render_template('share_transcript.html', owner=owner, filename=filename)

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
				print(idx)
				new_share = Shared_transcripts(filename, owner, shared_user, permissions[idx])
				db.session.add(new_share)
				db.session.commit()
				
		except IntegrityError as e:
			print(e)
			return jsonify("Unable to share transcript")
		
		
		return jsonify("Transcript successfully shared")
		
	else:
		return jsonify("not logged in")