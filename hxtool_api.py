try:
	from flask import Flask, request, Response, session, redirect, render_template, send_file, g, url_for, abort, Blueprint, current_app as app
	from jinja2 import evalcontextfilter, Markup, escape
except ImportError:
	print("hxtool requires the 'Flask' module, please install it.")
	exit(1)

from functools import wraps
from hx_lib import *
from hxtool_db import *

HXTOOL_API_VERSION = 1

ht_api = Blueprint('ht_api', __name__, template_folder='templates')

#ht_db = hxtool_db('hxtool.db', logger = app.logger)

def valid_session_required(f):
	@wraps(f)
	def is_session_valid(*args, **kwargs):
		if (session and 'ht_user' in session and 'ht_api_object' in session):
			o = HXAPI.deserialize(session['ht_api_object'])
			if o.restIsSessionValid():
				kwargs['hx_api_object'] = o
				return f(*args, **kwargs)
			else:
				app.logger.info("The HX API token for the current session has expired, redirecting to the login page.")
		return redirect(url_for('login', redirect_uri = request.full_path))	
	return is_session_valid

@ht_api.route('/api/v{0}/testcall'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_openioc():
	if request.method == 'GET':
		myiocs = ht_db.oiocList()
		return(app.response_class(response=json.dumps(myiocs), status=200, mimetype='application/json'))
