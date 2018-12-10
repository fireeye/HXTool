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
from hxtool_scheduler import *
from hxtool_task_modules import *

HXTOOL_API_VERSION = 1

ht_api = Blueprint('ht_api', __name__, template_folder='templates')


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
		
		#app.logger.info('Bulk acquisition action DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		#app.logger.info(format_activity_log(msg="bulk acquisition action", action="download", id=request.args.get('id'), hostset=hostset_id, user=session['ht_user'], controller=session['hx_ip']))
	#else:
		#app.logger.warn("No host entries were returned for bulk acquisition: {}. Did you just start the job? If so, wait for the hosts to be queued up.".format(request.args.get('id')))

	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))


# New bulk acquisiton from scriptstore
@ht_api.route('/api/v{0}/acquisition/bulk/new/db'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def hxtool_api_acquisition_bulk_new_db(hx_api_object):

	print(request.args.get('bulkhostset'))

	start_time = None
	interval = None
	
	if 'schedule' in request.args.keys():
		if request.args.get('schedule') == 'run_at':
			start_time = HXAPI.dt_from_str(request.form['scheduled_timestamp'])
		
		schedule = None	
		if request.args.get('schedule') == 'run_interval':
			schedule = {
				'minutes' : request.args.get('intervalMin', None),
				'hours'  : request.args.get('intervalHour', None),
				'day_of_week' : request.args.get('intervalWeek', None),
				'day_of_month' : request.args.get('intervalDay', None)
			}

	should_download = False
	
	bulk_acquisition_script = app.hxtool_db.scriptGet(request.args.get('script'))
	skip_base64 = True
	
	task_profile = None
	if request.form.get('taskprocessor', False):
		task_profile = request.args.get('taskprofile_id', None)
		should_download = True
		
	submit_bulk_job(hx_api_object, 
					int(request.args.get('bulkhostset')), 
					bulk_acquisition_script, 
					start_time = start_time, 
					schedule = schedule, 
					task_profile = task_profile, 
					download = should_download,
					skip_base64 = skip_base64,
					comment=request.args.get('bulkcomment'))
	#app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	
	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))

# New bulk acquisition from file
@ht_api.route('/api/v{0}/acquisition/bulk/new/file'.format(HXTOOL_API_VERSION), methods=['POST'])
@valid_session_required
def hxtool_api_acquisition_bulk_new_file(hx_api_object):
	print("TODO")
	return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))

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
		api_response['api_response'] = HXAPI.compat_str(response_data)

	rcode = 200
	if not ret and response_code:
		if response_code in [401, 404]:
			rcode = response_code
		else:
			rcode = 400

	return(api_response, rcode)

