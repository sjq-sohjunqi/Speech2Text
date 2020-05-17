from flask import render_template, flash, redirect, url_for, session
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm, ChangePassForm, ChangeNameForm

from S2T.models import User
from sqlalchemy.exc import IntegrityError

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
			flash(e)
			return render_template('signup.html', title='Sign Up', form=form)
		
		flash('Signup successful for user {}'.format(form.username.data))
		return redirect(url_for('index'))
	
	return render_template('signup.html', title='Sign Up', form=form)

@S2T.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		found_user = User.query.filter_by(username=form.data['username']).first()
		if found_user:
			authenticated_user = bcrypt.check_password_hash(found_user.password, form.data['password'])
			if authenticated_user:
				session['USER'] = found_user.username
				session['NAME'] = found_user.name
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
		return render_template('profile.html', name=name, title=name+'\'s Page', passform=passform, nameform=nameform)
	else:
		return redirect(url_for('login'))
	

