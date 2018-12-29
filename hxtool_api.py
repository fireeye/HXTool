#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from flask import Flask, request, Response, session, redirect, render_template, send_file, g, url_for, abort, Blueprint, current_app as app
	from jinja2 import evalcontextfilter, Markup, escape
except ImportError:
	print("hxtool requires the 'Flask' module, please install it.")
	exit(1)

import hxtool_global
from hx_lib import *
from hxtool_util import *
from hxtool_data_models import *
from hxtool_scheduler import *
from hxtool_task_modules import *

HXTOOL_API_VERSION = 1

ht_api = Blueprint('ht_api', __name__, template_folder='templates')
logger = hxtool_global.get_logger(__name__)

###################################
# Common User interface endpoints #
###################################

@ht_api.route('/api/v{0}/hostsets'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def testcall5(hx_api_object):
	if request.method == 'GET':
		(ret, response_code, response_data) = hx_api_object.restListHostsets()
		if ret:
			return(app.response_class(response=json.dumps(response_data), status=200, mimetype='application/json'))
		else:
			return('',response_code)

@ht_api.route('/api/v{0}/getHealth'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def getHealth(hx_api_object):
	myHealth = {}
	(ret, response_code, response_data) = hx_api_object.restGetControllerVersion()
	if ret:
		myHealth['status'] = "OK"
		myHealth['version'] = response_data['data']
		return(app.response_class(response=json.dumps(myHealth), status=200, mimetype='application/json'))
	else:
		myHealth['status'] = "FAIL"
		return(app.response_class(response=json.dumps(myHealth), status=200, mimetype='application/json'))


################
# Acquisitions #
################
@ht_api.route('/api/v{0}/acquisition/get'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_get(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restGetUrl(request.args.get('url'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/acquisition/download'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_download(hx_api_object):
	if request.args.get('id'):
		if request.args.get('content') == "json":
			(ret, response_code, response_data) = hx_api_object.restDownloadFile(request.args.get('id'), accept = "application/json")
		else:
			(ret, response_code, response_data) = hx_api_object.restDownloadFile(request.args.get('id'))
		if ret:
			flask_response = Response(iter_chunk(response_data))
			flask_response.headers['Content-Type'] = response_data.headers['Content-Type']
			flask_response.headers['Content-Disposition'] = response_data.headers['Content-Disposition']
			return flask_response
		else:
			(r, rcode) = create_api_response(ret, response_code, response_data)
			return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))
	else:
		abort(404)

@ht_api.route('/api/v{0}/acquisition/file'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_file(hx_api_object):

	if request.args.get('type') == "api":
		mode = True
	if request.args.get('type') == "raw":
		mode = False

	print(request.args)

	if '\\' in request.args.get('filepath'):
		fileName = request.args.get('filepath').rsplit("\\", 1)[1]
		filePath = request.args.get('filepath').rsplit("\\", 1)[0]
	elif '/' in request.args.get('filepath'):
		fileName = request.args.get('filepath').rsplit("/", 1)[1]
		filePath = request.args.get('filepath').rsplit("/", 1)[0]
		
	(ret, response_code, response_data) = hx_api_object.restAcquireFile(request.args.get('id'), filePath, fileName, mode)

	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

#####################
# Enterprise Search #
#####################
# Stop
@ht_api.route('/api/v{0}/enterprise_search/stop'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_enterprise_search_stop(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restCancelJob('searches', request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

# Remove
@ht_api.route('/api/v{0}/enterprise_search/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_enterprise_search_remove(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restDeleteJob('searches', request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

# New search from openioc store
@ht_api.route('/api/v{0}/enterprise_search/new/db'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_enterprise_search_new_db(hx_api_object):

	ioc_script = app.hxtool_db.oiocGet(request.args.get('ioc'))

	ignore_unsupported_items = True
	if 'esskipterms' in request.args.keys():
		if request.args.get('esskipterms') == "false":
			ignore_unsupported_items = False
		else:
			ignore_unsupported_items = True

	mydisplayname = "N/A"
	if 'displayname' in request.args.keys():
		mydisplayname = request.args.get("displayname")

	start_time = None
	schedule = None
	if 'schedule' in request.args.keys():
		if request.args.get('schedule') == 'run_at':
			start_time = HXAPI.dt_from_str(request.args.get('scheduled_timestamp'))
		
		if request.args.get('schedule') == 'run_interval':
			schedule = {
				'minutes' : request.args.get('intervalMin', None),
				'hours'  : request.args.get('intervalHour', None),
				'day_of_week' : request.args.get('intervalWeek', None),
				'day_of_month' : request.args.get('intervalDay', None)
			}	

	enterprise_search_task = hxtool_scheduler_task(session['ht_profileid'], "Enterprise Search Task", start_time = start_time)
	
	if schedule:
		enterprise_search_task.set_schedule(**schedule)
		
	enterprise_search_task.add_step(enterprise_search_task_module, kwargs = {
										'script' : ioc_script['ioc'],
										'hostset_id' : request.args.get('sweephostset'),
										'ignore_unsupported_items' : ignore_unsupported_items,
										'skip_base64': True,
										'displayname': mydisplayname
									})
	hxtool_global.hxtool_scheduler.add(enterprise_search_task)

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))

# New search from file
@ht_api.route('/api/v{0}/enterprise_search/new/file'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_enterprise_search_new_file(hx_api_object):

	fc = request.files['ioc']
	ioc_script = fc.read()

	ignore_unsupported_items = True
	if 'esskipterms' in request.form.keys():
		if request.form.get('esskipterms') == "false":
			ignore_unsupported_items = False
		else:
			ignore_unsupported_items = True

	mydisplayname = "N/A"
	if 'displayname' in request.form.keys():
		mydisplayname = request.form.get("displayname")

	start_time = None
	schedule = None
	if 'schedule' in request.form.keys():
		if request.form.get('schedule') == 'run_at':
			start_time = HXAPI.dt_from_str(request.form.get('scheduled_timestamp'))
		
		if request.form.get('schedule') == 'run_interval':
			schedule = {
				'minutes' : request.form.get('intervalMin', None),
				'hours'  : request.form.get('intervalHour', None),
				'day_of_week' : request.form.get('intervalWeek', None),
				'day_of_month' : request.form.get('intervalDay', None)
			}	

	enterprise_search_task = hxtool_scheduler_task(session['ht_profileid'], "Enterprise Search Task", start_time = start_time)
	
	if schedule:
		enterprise_search_task.set_schedule(**schedule)
		
	enterprise_search_task.add_step(enterprise_search_task_module, kwargs = {
										'script' : HXAPI.b64(ioc_script),
										'hostset_id' : request.form.get('sweephostset'),
										'ignore_unsupported_items' : ignore_unsupported_items,
										'skip_base64': True,
										'displayname': mydisplayname
									})
	hxtool_global.hxtool_scheduler.add(enterprise_search_task)

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


#########
# Hosts #
#########
@ht_api.route('/api/v{0}/hosts/get'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_hosts_get(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restGetHostSummary(request.args.get('id'))
	(r, rcode) = create_api_response(response_data = response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/hosts/sysinfo'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_hosts_sysinfo(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restGetHostSysinfo(request.args.get('id'))
	(r, rcode) = create_api_response(response_data = response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))


###################
# Manage OpenIOCs #
###################
@ht_api.route('/api/v{0}/openioc/view'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_openioc_view(hx_api_object):
	storedioc = hxtool_global.hxtool_db.oiocGet(request.args.get('id'))
	(r, rcode) = create_api_response(response_data = json.dumps(storedioc))
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/openioc/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_openioc_remove(hx_api_object):
	hxtool_global.hxtool_db.oiocDelete(request.args.get('id'))
	(r, rcode) = create_api_response()
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/openioc/upload'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_openioc_upload(hx_api_object):

	fc = request.files['myioc']
	rawioc = fc.read()
	hxtool_global.hxtool_db.oiocCreate(request.form['iocname'], HXAPI.b64(rawioc), session['ht_user'])
	(r, rcode) = create_api_response(ret=True)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

##########
# Alerts #
##########
@ht_api.route('/api/v{0}/alerts/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_alerts_remove(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restDeleteJob('alerts', request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/alerts/get'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_alerts_get(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restGetAlertID(request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))


#####################
# Alert Annotations #
#####################
@ht_api.route('/api/v{0}/annotation/add'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_annotation_add(hx_api_object):
	hxtool_global.hxtool_db.alertCreate(session['ht_profileid'], request.form['id'])
	hxtool_global.hxtool_db.alertAddAnnotation(session['ht_profileid'], request.form['id'], request.form['text'], request.form['state'], session['ht_user'])
	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/annotation/alert/view'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_annotation_alert_view(hx_api_object):
	alertAnnotations = hxtool_global.hxtool_db.alertGet(session['ht_profileid'], request.args.get('id'))
	return(app.response_class(response=json.dumps(alertAnnotations), status=200, mimetype='application/json'))


#############
# Scheduler #
#############

@ht_api.route('/api/v{0}/scheduler/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_scheduler_remove(hx_api_object):
	key_to_delete = request.args.get('id')

	for task in hxtool_global.hxtool_scheduler.tasks():
		if task['parent_id'] == key_to_delete:
			hxtool_global.hxtool_scheduler.remove(task['task_id'])

	hxtool_global.hxtool_scheduler.remove(key_to_delete)

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/scheduler_health'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def scheduler_health(hx_api_object):
	return(app.response_class(response=json.dumps(hxtool_global.hxtool_scheduler.status()), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/scheduler_tasks'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def scheduler_tasks(hx_api_object):
	mytasks = {}
	mytasks['data'] = []
	for task in hxtool_global.hxtool_scheduler.tasks():
		if not task['parent_id']:

			taskstates = {}
			for subtask in hxtool_global.hxtool_scheduler.tasks():
				if subtask['parent_id'] == task['task_id']:
					if not task_state_description.get(subtask['state'], "Unknown") in taskstates.keys():
						taskstates[task_state_description.get(subtask['state'], "Unknown")] = 1
					else:
						taskstates[task_state_description.get(subtask['state'], "Unknown")] += 1

			mytasks['data'].append({
				"DT_RowId": task['task_id'],
				"profile": task['profile_id'],
				"child_states": json.dumps(taskstates),
				"name": task['name'],
				"enabled": task['enabled'],
				"last_run": str(task['last_run']),
				"next_run": str(task['next_run']),
				"immutable": task['immutable'],
				"state": task_state_description.get(task['state'], "Unknown"),
				"action": task['task_id']
				})
	return(app.response_class(response=json.dumps(mytasks), status=200, mimetype='application/json'))


################
# Task profile #
################

@ht_api.route('/api/v{0}/taskprofile/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_taskprofile_remove(hx_api_object):

	app.hxtool_db.taskProfileDelete(request.args.get('id'))

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


####################
# Bulk Acquisition #
####################

# Remove
@ht_api.route('/api/v{0}/acquisition/bulk/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_remove(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

# Stop
@ht_api.route('/api/v{0}/acquisition/bulk/stop'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_stop(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', request.args.get('id'))
	(r, rcode) = create_api_response(ret, response_code, response_data)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

# Download
@ht_api.route('/api/v{0}/acquisition/bulk/download'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_download(hx_api_object):
	hostset_id = -1
	(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(request.args.get('id'))
	if ret:
		if 'host_set' in response_data['data']:
			hostset_id = int(response_data['data']['host_set']['_id'])
	
	(ret, response_code, response_data) = hx_api_object.restListBulkHosts(request.args.get('id'))
	
	if ret and response_data and len(response_data['data']['entries']) > 0:
		bulk_download_eid = app.hxtool_db.bulkDownloadCreate(session['ht_profileid'], hostset_id = hostset_id, task_profile = None)
		
		bulk_acquisition_hosts = {}
		task_list = []
		for host in response_data['data']['entries']:
			bulk_acquisition_hosts[host['host']['_id']] = {'downloaded' : False, 'hostname' :  host['host']['hostname']}
			bulk_acquisition_download_task = hxtool_scheduler_task(session['ht_profileid'], 'Bulk Acquisition Download: {}'.format(host['host']['hostname']))
			bulk_acquisition_download_task.add_step(bulk_download_task_module, kwargs = {
														'bulk_download_eid' : bulk_download_eid,
														'agent_id' : host['host']['_id'],
														'host_name' : host['host']['hostname']
													})
			# This works around a nasty race condition where the task would start before the download job was added to the database				
			task_list.append(bulk_acquisition_download_task)
		
		app.hxtool_db.bulkDownloadUpdate(bulk_download_eid, hosts = bulk_acquisition_hosts, bulk_acquisition_id = int(request.args.get('id')))
	
		hxtool_global.hxtool_scheduler.add_list(task_list)
		
		logger.info('Bulk acquisition action DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		logger.info(format_activity_log(msg="bulk acquisition action", action="download", id=request.args.get('id'), hostset=hostset_id, user=session['ht_user'], controller=session['hx_ip']))
	else:
		logger.warn("No host entries were returned for bulk acquisition: {}. Did you just start the job? If so, wait for the hosts to be queued up.".format(request.args.get('id')))

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


# New bulk acquisiton from scriptstore
@ht_api.route('/api/v{0}/acquisition/bulk/new/db'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_new_db(hx_api_object):

	start_time = None
	interval = None
	schedule = None
	
	if 'schedule' in request.args.keys():
		if request.args.get('schedule') == 'run_at':
			start_time = HXAPI.dt_from_str(request.args.get('scheduled_timestamp'))
		
		if request.args.get('schedule') == 'run_interval':
			schedule = {
				'minutes' : request.args.get('intervalMin', None),
				'hours'  : request.args.get('intervalHour', None),
				'day_of_week' : request.args.get('intervalWeek', None),
				'day_of_month' : request.args.get('intervalDay', None)
			}

	should_download = False
	
	bulk_acquisition_script = app.hxtool_db.scriptGet(request.args.get('bulkscript'))['script']
	skip_base64 = True
	
	task_profile = None
	if request.args.get('taskprocessor') != "false":
		task_profile = request.args.get('taskprocessor', None)
		should_download = True

	submit_bulk_job(hx_api_object, 
					int(request.args.get('bulkhostset')), 
					bulk_acquisition_script, 
					start_time = start_time, 
					schedule = schedule, 
					task_profile = task_profile, 
					download = should_download,
					skip_base64 = skip_base64,
					comment=request.args.get('displayname'))
	logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	
	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))

# New bulk acquisition from file
@ht_api.route('/api/v{0}/acquisition/bulk/new/file'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_acquisition_bulk_new_file(hx_api_object):

	start_time = None
	interval = None
	schedule = None
	
	if 'schedule' in request.form.keys():
		if request.form['schedule'] == 'run_at':
			start_time = HXAPI.dt_from_str(request.form['scheduled_timestamp'])
		
		if request.form['schedule'] == 'run_interval':
			schedule = {
				'minutes' : request.form.get('intervalMin', None),
				'hours'  : request.form.get('intervalHour', None),
				'day_of_week' : request.form.get('intervalWeek', None),
				'day_of_month' : request.form.get('intervalDay', None)
			}

	bulk_acquisition_script = None
	skip_base64 = False
	should_download = False
	
	f = request.files['bulkscript']
	bulk_acquisition_script = f.read()
	
	task_profile = None
	if request.form['taskprocessor'] != "false":
		task_profile = request.form.get('taskprocessor', None)
		should_download = True

	submit_bulk_job(hx_api_object, 
					int(request.form['bulkhostset']), 
					HXAPI.compat_str(bulk_acquisition_script), 
					start_time = start_time, 
					schedule = schedule, 
					task_profile = task_profile, 
					download = should_download,
					skip_base64 = skip_base64,
					comment=request.form['displayname'])
	logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


###########
# Scripts #
###########
@ht_api.route('/api/v{0}/scripts/remove'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_scripts_remove(hx_api_object):
	hxtool_global.hxtool_db.scriptDelete(request.args.get('id'))
	(r, rcode) = create_api_response(ret=True)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/scripts/upload'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_scripts_upload(hx_api_object):

	fc = request.files['myscript']
	rawscript = fc.read()
	hxtool_global.hxtool_db.scriptCreate(request.form['scriptname'], HXAPI.b64(rawscript), session['ht_user'])
	(r, rcode) = create_api_response(ret=True)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))

@ht_api.route('/api/v{0}/scripts/builder'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_scripts_builder(hx_api_object):
	mydata = request.get_json(silent=True)

	app.hxtool_db.scriptCreate(mydata['scriptName'], HXAPI.b64(json.dumps(mydata['script'], indent=4).encode()), session['ht_user'])
	app.logger.info(format_activity_log(msg="new scriptbuilder acquisiton script", name=mydata['scriptName'], user=session['ht_user'], controller=session['hx_ip']))

	(r, rcode) = create_api_response(ret=True)
	return(app.response_class(response=json.dumps(r), status=rcode, mimetype='application/json'))


##############
# Datatables #
##############

@ht_api.route('/api/v{0}/datatable_hosts_with_alerts'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_hosts_with_alerts(hx_api_object):
	if request.method == 'GET':

		myhosts = []

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=request.args.get('limit'), sort_term="stats.alerts+descending")
		if ret:
			for host in response_data['data']['entries']:
				myhosts.append([host['hostname'] + "___" + host['_id'], host['stats']['alerts']])
		else:
			return('', 500)

		mydata = {"data": myhosts[:10]}

		return(app.response_class(response=json.dumps(mydata), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/datatable_alerts_host'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_alerts_host(hx_api_object):
	if request.method == 'GET':

		myalerts = {"data": []}

		(ret, response_code, response_data) = hx_api_object.restGetAlerts(limit=request.args.get('limit'), filter_term={ "agent._id": request.args.get("host") })

		if ret:
			for alert in response_data['data']['entries']:
				# Query host object
				(hret, hresponse_code, hresponse_data) = hx_api_object.restGetHostSummary(alert['agent']['_id'])
				if ret:
					hostname = hresponse_data['data']['hostname']
					domain = hresponse_data['data']['domain']
					hid = hresponse_data['data']['_id']
					aid = alert['_id']
				else:
					hostname = "unknown"
					domain = "unknown"

				if alert['source'] == "IOC":
					(cret, cresponse_code, cresponse_data) = hx_api_object.restGetIndicatorFromCondition(alert['condition']['_id'])
					if cret:
						tname = cresponse_data['data']['entries'][0]['name']
					else:
						tname = "N/A"
				elif alert['source'] == "EXD":
					tname = "Exploit: " + HXAPI.compat_str(len(alert['event_values']['messages'])) + " behaviours"
				elif alert['source'] == "MAL":
					tname = HXAPI.compat_str(alert['event_values']['detections']['detection'][0]['infection']['infection-name'])
				else:
					tname = "N/A"

				myalerts['data'].append({
					"DT_RowId": alert['_id'],
					"event_at": HXAPI.dt_to_str(HXAPI.gtNoUs(alert['event_at'])),
					"source": alert['source'],
					"threat": tname,
					"resolution": alert['resolution']
				})
		else:
			return('', 500)

		return(app.response_class(response=json.dumps(myalerts), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/datatable_alerts'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_alerts(hx_api_object):
	if request.method == 'GET':

		myalerts = {"data": []}

		if 'source' in request.args:
			(ret, response_code, response_data) = hx_api_object.restGetAlerts(limit=request.args.get('limit'), filter_term={ "source": request.args.get("source") })
		else:
			(ret, response_code, response_data) = hx_api_object.restGetAlerts(limit=request.args.get('limit'))

		if ret:
			for alert in response_data['data']['entries']:
				# Query host object
				(hret, hresponse_code, hresponse_data) = hx_api_object.restGetHostSummary(alert['agent']['_id'])
				if ret:
					hostname = hresponse_data['data']['hostname']
					domain = hresponse_data['data']['domain']
					hid = hresponse_data['data']['_id']
					aid = alert['_id']
				else:
					hostname = "unknown"
					domain = "unknown"

				if alert['source'] == "IOC":
					(cret, cresponse_code, cresponse_data) = hx_api_object.restGetIndicatorFromCondition(alert['condition']['_id'])
					if cret:
						tname = cresponse_data['data']['entries'][0]['name']
					else:
						tname = "N/A"
				elif alert['source'] == "EXD":
					tname = "Exploit: " + HXAPI.compat_str(len(alert['event_values']['messages'])) + " behaviours"
				elif alert['source'] == "MAL":
					tname = HXAPI.compat_str(alert['event_values']['detections']['detection'][0]['infection']['infection-name'])
				else:
					tname = "N/A"


				myalerts['data'].append([HXAPI.compat_str(hostname) + "___" + HXAPI.compat_str(hid) + "___" + HXAPI.compat_str(aid), domain, alert['reported_at'], alert['source'], tname, alert['resolution']])
		else:
			return('', 500)

		return(app.response_class(response=json.dumps(myalerts), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/datatable_alerts_full'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_alerts_full(hx_api_object):
	if request.method == 'GET':

		myalerts = {"data": []}

		# hosts and ioc cache
		myhosts = {}
		myiocs = {}

		myfilters = {}
		if 'source' in request.args:
			myfilters['source'] = [request.args.get("source")]

		if 'resolution' in request.args:
			myfilters['resolution'] = request.args.get("resolution")

		if 'limit' in request.args:
			mylimit = int(request.args.get("limit"))
		else:
			mylimit = None

		if 'hostname' in request.args:
			(ret, response_code, response_data) = hx_api_object.restListHosts(search_term = request.args.get('hostname'))
			if ret:
				myhostlist = []
				for hostname in response_data['data']['entries']:
					myhostlist.append(hostname['_id'])
				myfilters['agent._id'] = myhostlist

		if len(myfilters) > 0:
			(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'), filters=myfilters, limit=mylimit)
		else:
			(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'), limit=mylimit)
		if ret:

			# Check if we need to match alertname
			if 'alertname' in request.args:

				myalertname = request.args.get("alertname")
				myMatches = []

				for alert in response_data:
					if alert['source'] == "MAL":
						for mymalinfo in alert['event_values']['detections']['detection']:
							try:
								if myalertname in mymalinfo['infection']['infection-name']:
									myMatches.append(alert)
							except(KeyError):
								continue
					if alert['source'] == "EXD":
						if myalertname in alert['event_values']['process_name']:
							myMatches.append(alert)
					if alert['source'] == "IOC":
						if alert['condition']['_id'] not in myiocs:
							# Query IOC object since we do not have it in memory
							(cret, cresponse_code, cresponse_data) = hx_api_object.restGetIndicatorFromCondition(alert['condition']['_id'])
							if cret:
								myiocs[alert['condition']['_id']] = cresponse_data['data']['entries'][0]
								tname = cresponse_data['data']['entries'][0]['name']
							else:
								tname = "N/A"
						else:
							tname = myiocs[alert['condition']['_id']]['name']
							if myalertname in tname:
								myMatches.append(alert)

				# overwrite data with our filtered list
				response_data = myMatches


			# Check if we need to match md5hash
			if 'md5hash' in request.args:

				myhash = request.args.get("md5hash")
				myMatches = []
				myIOCfields = ["fileWriteEvent/md5", "processEvent/md5"]

				for alert in response_data:
					if alert['source'] == "IOC":
						try:
							for mykey in myIOCfields:
								if alert['event_values'][mykey] == myhash:
									myMatches.append(alert)
						except(KeyError):
							continue

					elif alert['source'] == "EXD":
						EXDMatch = False
						for detail in alert['event_values']['analysis_details']:
							for itemkey, itemvalue in detail[detail['detail_type']].items():
								if (itemkey == "md5sum" and itemvalue == myhash):
									EXDMatch = True
								else:
									if itemkey == "processinfo":
										try:
											if detail[detail['detail_type']]['processinfo']['md5sum'] == myhash:
												EXDMatch = True
										except(KeyError):
											continue
						if EXDMatch:
							myMatches.append(alert)

					elif alert['source'] == "MAL":
						for detection in alert['event_values']['detections']['detection']:
							for myobjkey, myobjval in detection['infected-object'].items():
								if myobjkey == "file-object":
									try:
										if myobjval['md5sum'] == myhash:
											myMatches.append(alert)
									except(KeyError):
										continue
					else:
						continue

				response_data = myMatches


			# Get annotations from DB and store in memory
			myannotations = {}
			dbannotations = app.hxtool_db.alertList(session['ht_profileid'])
			for annotation in dbannotations:
				if not annotation['hx_alert_id'] in myannotations.keys():
					myannotations[annotation['hx_alert_id']] = {"max_state": 0, "count": len(annotation['annotations'])}

				for item in annotation['annotations']:
					if item['state'] > myannotations[annotation['hx_alert_id']]['max_state']:
						myannotations[annotation['hx_alert_id']]['max_state'] = item['state']

			for alert in response_data:

				if alert['_id'] in myannotations.keys():
					annotation_count = myannotations[alert['_id']]['count']
					annotation_max_state = myannotations[alert['_id']]['max_state']
				else:
					annotation_count = 0
					annotation_max_state = 0

				
				if alert['agent']['_id'] not in myhosts:
					# Query host object since we do not have it in memory
					(hret, hresponse_code, hresponse_data) = hx_api_object.restGetHostSummary(alert['agent']['_id'])
					if ret:
						myhosts[alert['agent']['_id']] = hresponse_data['data']
				
				hostname = myhosts[alert['agent']['_id']]['hostname']
				domain = myhosts[alert['agent']['_id']]['domain']
				hid = myhosts[alert['agent']['_id']]['_id']
				aid = alert['_id']
				if HXAPI.compat_str(myhosts[alert['agent']['_id']]['os']['product_name']).startswith('Windows'):
					platform = "win"
				elif HXAPI.compat_str(myhosts[alert['agent']['_id']]['os']['product_name']).startswith('Mac'):
					platform = "mac"
				else:
					platform = "linux"

				
				if alert['source'] == "IOC":
					if alert['condition']['_id'] not in myiocs:
						# Query IOC object since we do not have it in memory
						(cret, cresponse_code, cresponse_data) = hx_api_object.restGetIndicatorFromCondition(alert['condition']['_id'])
						if cret:
							myiocs[alert['condition']['_id']] = cresponse_data['data']['entries'][0]
							tname = cresponse_data['data']['entries'][0]['name']
						else:
							tname = "N/A"
					else:
						tname = myiocs[alert['condition']['_id']]['name']

				elif alert['source'] == "EXD":
					tname = "Exploit: " + HXAPI.compat_str(len(alert['event_values']['messages'])) + " behaviours"
				elif alert['source'] == "MAL":
					tname = HXAPI.compat_str(alert['event_values']['detections']['detection'][0]['infection']['infection-name'])
				else:
					tname = "N/A"

				myalerts['data'].append({
					"DT_RowId": alert['_id'],
					"platform": platform,
					"hostname": HXAPI.compat_str(hostname) + "___" + HXAPI.compat_str(hid) + "___" + HXAPI.compat_str(aid),
					"domain": domain,
					"event_at": alert['event_at'],
					"matched_at": alert['matched_at'],
					"reported_at": alert['reported_at'],
					"containment_state": alert['agent']['containment_state'],
					"age": HXAPI.prettyTime(HXAPI.gt(alert['event_at'])),
					"source": alert['source'],
					"threat": tname,
					"resolution": alert['resolution'],
					"annotation_max_state": annotation_max_state,
					"annotation_count": annotation_count,
					"action": alert['_id']
					})
		else:
			return('', 500)

		return(app.response_class(response=json.dumps(myalerts), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/datatable_scripts'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_scripts(hx_api_object):
	if request.method == 'GET':
		myscripts = app.hxtool_db.scriptList()
		return(app.response_class(response=json.dumps(myscripts), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/datatable_openioc'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_openioc(hx_api_object):
	if request.method == 'GET':
		myiocs = app.hxtool_db.oiocList()
		return(app.response_class(response=json.dumps(myiocs), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/datatable_taskprofiles'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_taskprofiles(hx_api_object):
	if request.method == 'GET':
		mytaskprofiles = app.hxtool_db.taskProfileList()
		return(app.response_class(response=json.dumps(mytaskprofiles), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/datatable_acqs'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_acqs(hx_api_object):
	if request.method == 'GET':
			myacqs = {"data": []}
			(ret, response_code, response_data) = hx_api_object.restListAllAcquisitions(limit=500)
			if ret:
				for acq in response_data['data']['entries']:
					if acq['type'] != "bulk":
						(hret, hresponse_code, hresponse_data) = hx_api_object.restGetHostSummary(acq['host']['_id'])
						if ret:
							myacqs['data'].append({
								"DT_RowId": acq['acq']['_id'],
								"type": acq['type'],
								"request_time": acq['request_time'],
								"state": acq['state'],
								"hostname": hresponse_data['data']['hostname'] + "___" + hresponse_data['data']['_id'],
								"domain": hresponse_data['data']['domain'],
								"containment_state": hresponse_data['data']['containment_state'],
								"last_poll_timestamp": hresponse_data['data']['last_poll_timestamp'],
								"platform": hresponse_data['data']['os']['platform'],
								"product_name": hresponse_data['data']['os']['product_name'],
								"action": acq['acq']['_id']
							})
				return(app.response_class(response=json.dumps(myacqs), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/datatable_acqs_host'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_acqs_host(hx_api_object):
	if request.method == 'GET':
			myacqs = {"data": []}
			(ret, response_code, response_data) = hx_api_object.restListAllAcquisitions(limit=500, filter_term={ "host._id": request.args.get("host") })
			if ret:
				for acq in response_data['data']['entries']:
					if 'url' in acq['acq'].keys():
						myacqurl = acq['acq']['url']
					elif (acq['type'] == "live"):
						myacqurl = "/hx/api/v3/acqs/live/" + HXAPI.compat_str(acq['acq']['_id'])
					else:
						myacqurl = False

					myacqs['data'].append({
						"DT_RowId": myacqurl,
						"type": acq['type'],
						"request_time": HXAPI.dt_to_str(HXAPI.gtNoUs(acq['request_time'])),
						"state": acq['state']
					})
				return(app.response_class(response=json.dumps(myacqs), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/datatable_es'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_es(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListSearches()
	if ret:
		mysearches = {"data": []}
		for search in response_data['data']['entries']:

			# Check for the existance of displayname, HX 4.5.0 and older doesn't have it
			if search['settings']['displayname']:
				displayname = search['settings']['displayname']
			else:
				displayname = "N/A"

			mysearches['data'].append({
				"DT_RowId": search['_id'],
				"state": search['state'],
				"displayname": displayname,
				"update_time": search['update_time'],
				"create_time": search['create_time'],
				"update_actor": search['update_actor']['username'],
				"create_actor": search['create_actor']['username'],
				"input_type": search['input_type'],
				"host_set": search['host_set']['name'],
				"host_set_id": search['host_set']['_id'],
				"stat_new": search['stats']['running_state']['NEW'],
				"stat_queued": search['stats']['running_state']['QUEUED'],
				"stat_failed": search['stats']['running_state']['FAILED'],
				"stat_complete": search['stats']['running_state']['COMPLETE'],
				"stat_aborted": search['stats']['running_state']['ABORTED'],
				"stat_cancelled": search['stats']['running_state']['CANCELLED'],
				"stat_hosts": search['stats']['hosts'],
				"stat_skipped_hosts": search['stats']['skipped_hosts'],
				"stat_searchstate_pending": search['stats']['search_state']['PENDING'],
				"stat_searchstate_matched": search['stats']['search_state']['MATCHED'],
				"stat_searchstate_notmatched": search['stats']['search_state']['NOT_MATCHED'],
				"stat_searchstate_error": search['stats']['search_state']['ERROR'],
				"mode": search['settings']['mode']
			})
		return(app.response_class(response=json.dumps(mysearches), status=200, mimetype='application/json'))
	else:
		return('HX API Call failed',500)

@ht_api.route('/api/v{0}/datatable_bulk'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_bulk(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
	if ret:
		mybulk = {"data": []}
		for acq in response_data['data']['entries']:

			# Find the host-set id. We have to do this because in some cases hostset is kept in comment and in some cases not.
			# TODO: remove host set in comment code after several releases. This should no longer be used.
			if acq['host_set']:
				try:
					myhostsetid = acq['host_set']['_id']
				except(KeyError):
					myhostsetid = False
			else:
				if acq['comment']:
					try:
						mycommentdata = json.loads(acq['comment'])
					except(ValueError):
						myhostsetid = False
					else:
						myhostsetid = mycommentdata['hostset_id']
				else:
					myhostsetid = False

			# Find hostset name
			if myhostsetid:
				if myhostsetid != 9:
					(hret, hresponse_code, hresponse_data) = hx_api_object.restListHostsets(filter_term={"_id": myhostsetid})
					if ret and len(hresponse_data['data']['entries']) > 0:
						try:
							myhostsetname = hresponse_data['data']['entries'][0]['name']
						except(KeyError):
							myhostsetname = HXAPI.compat_str(myhostsetid)
					else:
						myhostsetname = HXAPI.compat_str(myhostsetid)
				else:
					myhostsetname = "All Hosts"
			else:
				myhostsetname = "N/A"

			# Comlete rate
			total_size = acq['stats']['running_state']['NEW'] + acq['stats']['running_state']['QUEUED'] + acq['stats']['running_state']['FAILED'] + acq['stats']['running_state']['ABORTED'] + acq['stats']['running_state']['DELETED'] + acq['stats']['running_state']['REFRESH'] + acq['stats']['running_state']['CANCELLED'] + acq['stats']['running_state']['COMPLETE']
			if total_size == 0:
				completerate = 0
			else:
				completerate = int(float(acq['stats']['running_state']['COMPLETE']) / float(total_size) * 100)
			
			if completerate > 100:
				completerate = 100

			# Download rate
			bulk_download = app.hxtool_db.bulkDownloadGet(profile_id = session['ht_profileid'], bulk_acquisition_id = acq['_id'])

			if bulk_download:
				total_hosts = len(bulk_download['hosts'])
				hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
				if total_hosts > 0 and hosts_completed > 0:
					
					dlprogress = int(float(hosts_completed) / total_hosts * 100)
								
					if dlprogress > 100:
						dlprogress = 100

				else:
					dlprogress = 0
			else:
				dlprogress = "N/A"

			# Handle buttons
			myaction = acq['_id']
			if bulk_download and bulk_download['task_profile']:
				if bulk_download['task_profile'] in ["file_listing","stacking"]:
					myaction = bulk_download['task_profile']

			mybulk['data'].append({
				"DT_RowId": acq['_id'],
				"state": acq['state'],
				"comment": acq['comment'],
				"hostset": myhostsetname,
				"create_time": acq['create_time'],
				"update_time": acq['update_time'],
				"create_actor": acq['create_actor']['username'],
				"stat_runtime_avg": acq['stats']['run_time']['avg'],
				"stat_runtime_min": acq['stats']['run_time']['min'],
				"stat_runtime_max": acq['stats']['run_time']['max'],
				"total_size": acq['stats']['total_size'],
				"task_size_avg": acq['stats']['task_size']['avg'],
				"task_size_min": acq['stats']['task_size']['min'],
				"task_size_max": acq['stats']['task_size']['max'],
				"running_state_new": acq['stats']['running_state']['NEW'],
				"running_state_queued": acq['stats']['running_state']['QUEUED'],
				"running_state_failed": acq['stats']['running_state']['FAILED'],
				"running_state_complete": acq['stats']['running_state']['COMPLETE'],
				"running_state_aborted": acq['stats']['running_state']['ABORTED'],
				"running_state_cancelled": acq['stats']['running_state']['CANCELLED'],
				"completerate": completerate,
				"downloadrate": dlprogress,
				"action": myaction
			})
		return(app.response_class(response=json.dumps(mybulk), status=200, mimetype='application/json'))
	else:
		return('HX API Call failed',500)



@ht_api.route('/api/v{0}/datatable_es_result_types'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_es_result_types(hx_api_object):
	if request.args.get('id'):
		mytypes = {}
		(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'), limit=30000)
		if ret:
			for host in response_data['data']['entries']:
				for event in host['results']:
					if not event['type'] in mytypes:
						mytypes[event['type']] = ['hostname']
					for key, val in event.items():
						if not key.replace(" ", "_") in mytypes[event['type']]:
							if key == "data":
								for datakey in val.keys():
									if not datakey.replace(" ", "_") in mytypes[event['type']]:
										mytypes[event['type']].append(datakey.replace(" ", "_"))
							elif key == "type":
								mytypes[event['type']].append(key.replace(" ", "_"))


			return(app.response_class(response=json.dumps(mytypes), status=200, mimetype='application/json'))
		else:
			return('HX API Call failed', 500)
	else:
		return('Missing search id', 404)


@ht_api.route('/api/v{0}/datatable_es_result'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_es_result(hx_api_object):
	if request.args.get('id') and request.args.get('type'):
		myresult = {"data": []}
		(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'), limit=30000)
		if ret:
			for host in response_data['data']['entries']:
				for event in host['results']:
					if event['type'] == request.args.get('type'):
						mytempdict = {"DT_RowId": host['host']['_id'], "hostname": host['host']['hostname'] + "___" + host['host']['_id']}
						for eventitemkey, eventitemvalue in event.items():
							if eventitemkey == "data":
								for datakey, datavalue in eventitemvalue.items():
									mytempdict[datakey.replace(" ", "_")] = datavalue
							elif eventitemkey == "id":
								continue
							else:
								mytempdict[eventitemkey.replace(" ", "_")] = eventitemvalue
						myresult['data'].append(mytempdict)

			return(app.response_class(response=json.dumps(myresult), status=200, mimetype='application/json'))
		else:
			return('HX API Call failed', 500)
	else:
		return('Missing search id or type', 404)


###########
# ChartJS #
###########

@ht_api.route('/api/v{0}/chartjs_malwarecontent'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_malwarecontent(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0
		myData = {}
		myData['labels'] = []
		myData['datasets'] = []

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(host['_id'])
				if sret and 'malware' in sresponse_data['data'].keys():
					if 'content' in sresponse_data['data']['malware'].keys():
						if not sresponse_data['data']['malware']['content']['version'] in myContent.keys():
							myContent[sresponse_data['data']['malware']['content']['version']] = 1
						else:
							myContent[sresponse_data['data']['malware']['content']['version']] += 1
					else:
						myContent['none'] += 1
				else:
					myContent['none'] += 1

		dataset = []
		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "version": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		for entry in results:
			myData['labels'].append(entry['version'])
			dataset.append(entry['count'])

#		myPattern = get_N_HexCol(len(results))
		myPattern = ["#0fb8dc", "#006b8c", "#fb715e", "#59dc90", "#11a962", "#99ddff", "#ffe352", "#f0950e", "#ea475b", "#00cbbe"]

		myData['datasets'] = []
		myData['datasets'].append({
			"label": "content version",
			"backgroundColor": myPattern,
			"borderColor": "#0d1a2b",
			"borderWidth": 5,
			"data": dataset
			})

		return(app.response_class(response=json.dumps(myData), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/chartjs_malwareengine'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_malwareengine(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0
		myData = {}
		myData['labels'] = []
		myData['datasets'] = []

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(host['_id'])
				if sret and 'malware' in sresponse_data['data'].keys():
					if 'content' in sresponse_data['data']['malware'].keys():
						if not sresponse_data['data']['malware']['engine']['version'] in myContent.keys():
							myContent[sresponse_data['data']['malware']['engine']['version']] = 1
						else:
							myContent[sresponse_data['data']['malware']['engine']['version']] += 1
					else:
						myContent['none'] += 1
				else:
					myContent['none'] += 1

		dataset = []
		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "version": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		for entry in results:
			myData['labels'].append(entry['version'])
			dataset.append(entry['count'])

		myPattern = ["#0fb8dc", "#006b8c", "#fb715e", "#59dc90", "#11a962", "#99ddff", "#ffe352", "#f0950e", "#ea475b", "#00cbbe"]

		myData['datasets'] = []
		myData['datasets'].append({
			"label": "engine version",
			"backgroundColor": myPattern,
			"borderColor": "#0d1a2b",
			"borderWidth": 5,
			"data": dataset
			})

		return(app.response_class(response=json.dumps(myData), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/chartjs_malwarestatus'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_malwarestatus(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0
		myData = {}
		myData['labels'] = []
		myData['datasets'] = []

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(host['_id'])
				if 'MalwareProtectionStatus' in sresponse_data['data'].keys():
					if not sresponse_data['data']['MalwareProtectionStatus'] in myContent.keys():
						myContent[sresponse_data['data']['MalwareProtectionStatus']] = 1
					else:
						myContent[sresponse_data['data']['MalwareProtectionStatus']] += 1
				else:
					myContent['none'] += 1

		dataset = []
		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "mode": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		for entry in results:
			myData['labels'].append(entry['mode'])
			dataset.append(entry['count'])

		myPattern = ["#0fb8dc", "#006b8c", "#fb715e", "#59dc90", "#11a962", "#99ddff", "#ffe352", "#f0950e", "#ea475b", "#00cbbe"]

		myData['datasets'] = []
		myData['datasets'].append({
			"label": "mode",
			"backgroundColor": myPattern,
			"borderColor": "#0d1a2b",
			"borderWidth": 5,
			"data": dataset
			})

		return(app.response_class(response=json.dumps(myData), status=200, mimetype='application/json'))

@ht_api.route('/api/v{0}/enterprise_search/chartjs_searches'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_enterprise_search_chartjs_searches(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListSearches()
	(r, rcode) = create_api_response(ret, response_code, response_data)
	if ret:
		mysearches = {}
		myGraphData = []
		myr = {}
		myr['labels'] = []
		myr['datasets'] = []

		startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
		endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
		delta = (endDate - startDate)

		# Generate data for all dates
		date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
		for date in date_list[::-1]:
			mysearches[date.strftime("%Y-%m-%d")] = 0

		for search in response_data['data']['entries']:

			if search['create_time'][0:10] in mysearches.keys():
				mysearches[search['create_time'][0:10]] += 1

		for key, val in mysearches.items():
			myr['labels'].append(key)
			myGraphData.append(val)

		myr['datasets'].append({
			"label": "Search count",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#8fffc1",
			"pointStyle": "circle",
			"pointRadius": 2,
			"data": myGraphData
		})

		return(app.response_class(response=json.dumps(myr), status=rcode, mimetype='application/json'))
	else:
		return('HX API Call failed',500)


@ht_api.route('/api/v{0}/acquisition/bulk/chartjs_acquisitions'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_chartjs_acquisitions(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
	(r, rcode) = create_api_response(ret, response_code, response_data)
	if ret:
		mysearches = {}
		myGraphData = []
		myr = {}
		myr['labels'] = []
		myr['datasets'] = []

		startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
		endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
		delta = (endDate - startDate)

		# Generate data for all dates
		date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
		for date in date_list[::-1]:
			mysearches[date.strftime("%Y-%m-%d")] = 0

		for search in response_data['data']['entries']:

			if search['create_time'][0:10] in mysearches.keys():
				mysearches[search['create_time'][0:10]] += 1

		for key, val in mysearches.items():
			myr['labels'].append(key)
			myGraphData.append(val)

		myr['datasets'].append({
			"label": "Bulk count",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#8fffc1",
			"pointStyle": "circle",
			"pointRadius": 2,
			"data": myGraphData
		})

		return(app.response_class(response=json.dumps(myr), status=rcode, mimetype='application/json'))
	else:
		return('HX API Call failed',500)


@ht_api.route('/api/v{0}/chartjs_hosts_initial_agent_checkin'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_hosts_initial_agent_checkin(hx_api_object):

	myhosts = {}
	myhosts['labels'] = []
	myhosts['datasets'] = []
	mycount = {}

	# Get all dates and calculate delta
	startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
	endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
	delta = (endDate - startDate)

	# Generate data for all dates
	date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
	for date in date_list[::-1]:
		mycount[date.strftime("%Y-%m-%d")] = 0

	(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
	if ret:
		for host in response_data['data']['entries']:
			if host['initial_agent_checkin'][0:10] in mycount.keys():
				mycount[host['initial_agent_checkin'][0:10]] += 1

		myGraphData = []
		for key, stats in mycount.items():
			myhosts['labels'].append(key)
			myGraphData.append(stats)

		myhosts['datasets'].append({
			"label": "Provisioned endpoints",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#8fffc1",
			"pointStyle": "circle",
			"pointRadius": 2,
	        "data": myGraphData
			})
	else:
		return('', 500)

	return(app.response_class(response=json.dumps(myhosts), status=200, mimetype='application/json'))


@ht_api.route('/api/v{0}/chartjs_events_timeline'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_events_timeline(hx_api_object):

	mydates = {}
	mydates['labels'] = []
	mydates['datasets'] = []
	mycount = {}

	# Get all dates and calculate delta
	startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
	endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
	delta = (endDate - startDate)

	# Generate data for all dates
	date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
	for date in date_list[::-1]:
		mycount[date.strftime("%Y-%m-%d")] = {"IOC": 0, "EXD": 0, "MAL": 0}

	# Get alerts
	(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'))
	if ret:
		for alert in response_data:
			# Make sure the date exists
			if not alert['event_at'][0:10] in mycount.keys():
				mycount[alert['event_at'][0:10]] = {"IOC": 0, "EXD": 0, "MAL": 0}

			# Add stats for date
			mycount[alert['event_at'][0:10]][alert['source']] += 1

		myDataIOC = []
		myDataEXD = []
		myDataMAL = []

		for key, stats in mycount.items():
			mydates['labels'].append(key)
			myDataIOC.append(stats['IOC'])
			myDataEXD.append(stats['EXD'])
			myDataMAL.append(stats['MAL'])

		mydates['datasets'].append({
			"label": "IOC",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#8fffc1",
			"pointStyle": "circle",
			"pointRadius": 2,
			"data": myDataIOC
		})
		mydates['datasets'].append({
			"label": "EXD",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#b20032",
			"pointStyle": "circle",
			"pointRadius": 2,
			"data": myDataEXD
		})
		mydates['datasets'].append({
			"label": "MAL",
			"backgroundColor": "rgba(17, 169, 98, 0.2)",
			"borderWidth": 2,
			"borderColor": "#ffe352",
			"pointStyle": "circle",
			"pointRadius": 2,
			"data": myDataMAL
		})

		return(app.response_class(response=json.dumps(mydates), status=200, mimetype='application/json'))
	else:
		return('',500)


@ht_api.route('/api/v{0}/chartjs_host_alert_timeline'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_host_alert_timeline(hx_api_object):

	mydates = {}
	mydates['datasets'] = []

	myIOC = {
		"label": "IOC",
		"backgroundColor": "rgba(17, 169, 98, 0.2)",
		"borderWidth": 2,
		"borderColor": "#8fffc1",
		"pointStyle": "circle",
		"pointRadius": 2,
		"data": []
	}
	myEXD = {
		"label": "EXD",
		"backgroundColor": "rgba(17, 169, 98, 0.2)",
		"borderWidth": 2,
		"borderColor": "#b20032",
		"pointStyle": "circle",
		"pointRadius": 2,
		"data": []
	}
	myMAL = {
		"label": "MAL",
		"backgroundColor": "rgba(17, 169, 98, 0.2)",
		"borderWidth": 2,
		"borderColor": "#ffe352",
		"pointStyle": "circle",
		"pointRadius": 2,
		"data": []
	}

	mydates['datasets'].append(myIOC)
	mydates['datasets'].append(myEXD)
	mydates['datasets'].append(myMAL)

	(ret, response_code, response_data) = hx_api_object.restGetAlerts(filter_term={"agent._id": request.args.get("id")})
	if ret:
		for alert in response_data['data']['entries']:

			if alert['source'] == "IOC":
				mydates['datasets'][0]['data'].append({"x": alert['event_at'][0:19].replace("T", " "), "y": 1})

			if alert['source'] == "EXD":
				mydates['datasets'][1]['data'].append({"x": alert['event_at'][0:19].replace("T", " "), "y": 1})

			if alert['source'] == "MAL":
				mydates['datasets'][2]['data'].append({"x": alert['event_at'][0:19].replace("T", " "), "y": 1})

		return(app.response_class(response=json.dumps(mydates), status=200, mimetype='application/json'))
	else:
		return('',500)


@ht_api.route('/api/v{0}/chartjs_events_distribution'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_events_distribution(hx_api_object):

	mydata = {}
	mydata['labels'] = []
	mydata['datasets'] = []
	mycount = {}

	# Get alerts
	(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'))
	if ret:
		for alert in response_data:
			# Make sure the key exists
			if not alert['source'] in mycount.keys():
				mycount[alert['source']] = 0

			# Add stats
			mycount[alert['source']] += 1

		mydata['labels'].append("IOC")
		mydata['labels'].append("EXD")
		mydata['labels'].append("MAL")

		if 'IOC' in mycount.keys():
			myDataIOC = mycount["IOC"]
		else:
			myDataIOC = 0
		if 'EXD' in mycount.keys():
			myDataEXD = mycount["EXD"]
		else:
			myDataEXD = 0
		if 'MAL' in mycount.keys():
			myDataMAL = mycount["MAL"]
		else:
			myDataMAL = 0

		mydata['datasets'].append({
			"label": "Alert count",
			"backgroundColor": "rgba(0, 203, 190, 0.6)",
			"borderColor": "rgba(0, 203, 190, 0.5)",
			"borderWidth": 3,
			"data": [myDataIOC, myDataEXD, myDataMAL]
		})


		return(app.response_class(response=json.dumps(mydata), status=200, mimetype='application/json'))
	else:
		return('',500)


@ht_api.route('/api/v{0}/chartjs_inactive_hosts_per_hostset'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def chartjs_inactive_hosts_per_hostset(hx_api_object):

	myhosts = []
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	if ret:
		for hostset in response_data['data']['entries']:
			(hret, hresponse_code, hresponse_data) = hx_api_object.restListHosts(query_terms = {'host_sets._id' : hostset['_id']})
			if ret:
				now = datetime.datetime.utcnow()
				hcount = 0
				for host in hresponse_data['data']['entries']:
					x = (HXAPI.gt(host['last_poll_timestamp']))
					if (int((now - x).total_seconds())) > int(request.args.get('seconds')):
						hcount += 1
				myhosts.append({"hostset": hostset['name'], "count": hcount})

		# Return the Vega Data
		newlist = sorted(myhosts, key=lambda k: k['count'])
		results = newlist[-10:]

		mydata = {}
		mydata['labels'] = []
		mydata['datasets'] = []

		tempData = []
		for setname in results[::-1]:
			mydata['labels'].append(setname['hostset'])
			tempData.append(setname['count'])

		mydata['datasets'].append({
			"label": "Missing hosts",
			"backgroundColor": "rgba(0, 203, 190, 0.6)",
			"borderColor": "rgba(0, 203, 190, 0.5)",
			"borderWidth": 3,
			"data": tempData
		})	

		return(app.response_class(response=json.dumps(mydata), status=200, mimetype='application/json'))
	else:
		return('',500)


######################
# Profile Management #
######################

@ht_api.route('/api/v{0}/profile'.format(HXTOOL_API_VERSION), methods=['GET', 'PUT'])
def profile():
	if request.method == 'GET':
		profiles = app.hxtool_db.profileList()
		return json.dumps({'data_count' :  len(profiles), 'data' : profiles})
	elif request.method == 'PUT':
		request_json = request.json
		if validate_json(['hx_name', 'hx_host', 'hx_port'], request_json):
			if app.hxtool_db.profileCreate(request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				logger.info("New controller profile added")
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
				logger.info("Controller profile %d modified.", profile_id)
				return make_response_by_code(200)
	elif request.method == 'DELETE':
		if app.hxtool_db.profileDelete(profile_id):
			logger.info("Controller profile %s deleted.", profile_id)
			return make_response_by_code(200)
		else:
			return make_response_by_code(404)


####################
# Stacking Results #
####################

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


def create_api_response(ret = True, response_code = 200, response_data = False):

	api_response = {}
	api_response['api_success'] = ret
	api_response['api_response_code'] = response_code

	if response_data:
		api_response['api_response'] = json.dumps(response_data)

	rcode = 200
	if not ret and response_code:
		if response_code in [401, 404]:
			rcode = response_code
		else:
			rcode = 400

	return(api_response, rcode)

