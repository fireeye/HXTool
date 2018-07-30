#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from flask import Flask, request, Response, session, redirect, render_template, send_file, g, url_for, abort, Blueprint, current_app as app
	from jinja2 import evalcontextfilter, Markup, escape
except ImportError:
	print("hxtool requires the 'Flask' module, please install it.")
	exit(1)

from hx_lib import *
from hxtool_util import *
from hxtool_data_models import *

HXTOOL_API_VERSION = 1

ht_api = Blueprint('ht_api', __name__, template_folder='templates')

@ht_api.route('/api/v{0}/testcall'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_openioc():
	if request.method == 'GET':
		myiocs = app.hxtool_db.oiocList()
		return(app.response_class(response=json.dumps(myiocs), status=200, mimetype='application/json'))

		
####################
# Profile Management
####################
@ht_api.route('/api/v{0}/profile'.format(HXTOOL_API_VERSION), methods=['GET', 'PUT'])
def profile():
	if request.method == 'GET':
		profiles = app.hxtool_db.profileList()
		return json.dumps({'data_count' :  len(profiles), 'data' : profiles})
	elif request.method == 'PUT':
		request_json = request.json
		if validate_json(['hx_name', 'hx_host', 'hx_port'], request_json):
			if app.hxtool_db.profileCreate(request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				app.logger.info("New controller profile added")
				return make_response_by_code(200)
		else:
			return make_response_by_code(400)
			
@ht_api.route('/api/v{0}/profile/<profile_id>'.format(HXTOOL_API_VERSION), methods=['GET', 'PUT', 'DELETE'])
def profile_by_id(profile_id):
	if request.method == 'GET':
		profile_object = app.hxtool_db.profileGet(profile_id)
		if profile_object:
			return json.dumps({'data' : profile_object})
		else:
			return make_response_by_code(404)
	elif request.method == 'PUT':
		request_json = request.json
		if validate_json(['profile_id', 'hx_name', 'hx_host', 'hx_port'], request_json):
			if app.hxtool_db.profileUpdate(request_json['_id'], request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				app.logger.info("Controller profile %d modified.", profile_id)
				return make_response_by_code(200)
	elif request.method == 'DELETE':
		if app.hxtool_db.profileDelete(profile_id):
			app.logger.info("Controller profile %s deleted.", profile_id)
			return make_response_by_code(200)
		else:
			return make_response_by_code(404)

#####################
# Stacking Results
#####################
@ht_api.route('/api/v{0}/stacking/<int:stack_job_eid>/results'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def stack_job_results(hx_api_object, stack_job_eid):
	stack_job = app.hxtool_db.stackJobGet(stack_job_eid = stack_job_eid)
	
	if stack_job is None:
		return make_response_by_code(404)

	if session['ht_profileid'] != stack_job['profile_id']:
		return make_response_by_code(401)
		
	ht_data_model = hxtool_data_models(stack_job['stack_type'])
	return ht_data_model.stack_data(stack_job['results'])	
			