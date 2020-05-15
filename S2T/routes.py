from flask import render_template, flash, redirect, url_for
from S2T import S2T, db, bcrypt
from S2T.forms import LoginForm, SignUpForm

from S2T.models import User
from sqlalchemy.exc import IntegrityError

@S2T.route('/')
@S2T.route('/index')
def index():
	user = {'username': 'Miguel'}
	return render_template('index.html', title='Home', user=user)

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
			return render_template('signup.html', form=form)
		
		flash('Signup successful for user {}'.format(form.username.data))
		return redirect(url_for('index'))
	
	return render_template('signup.html', form=form)

@S2T.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		found_user = User.query.filter_by(username=form.data['username']).first()
		if found_user:
			authenticated_user = bcrypt.check_password_hash(found_user.password, form.data['password'])
			if authenticated_user:
				flash('Login successful for user {}'.format(form.username.data))
			else:
				flash('Login unsuccessful for user {}'.format(form.username.data))
		else:
			flash('No such user {}'.format(form.username))
		
		return redirect(url_for('index'))
	return render_template('login.html', title='Sign In', form=form)