from flask import render_template
from S2T import S2T

@S2T.route('/')
@S2T.route('/index')
def index():
	user = {'username': 'Miguel'}
	return render_template('index.html', title='Home', user=user)
