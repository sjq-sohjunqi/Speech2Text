from S2T import S2T, db

@S2T.before_first_request
def setup():
	db.create_all()