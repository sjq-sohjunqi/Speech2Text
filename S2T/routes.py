from flask import render_template
from S2T import S2T
from S2T.forms import LoginForm

@S2T.route('/')
@S2T.route('/index')
def index():
	user = {'username': 'Miguel'}
	return render_template('index.html', title='Home', user=user)

@S2T.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		flash('Login requested for user {}, remember_me={}'.format(
			form.username.data, form.remember_me.data))
		return redirect('/index')
	return render_template('login.html', title='Sign In', form=form)