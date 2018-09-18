#!/usr/bin/env python
# -*- coding: utf-8 -*-

##################################################
# hxTool - 3rd party user-interface for FireEye HX 
#
# Henrik Olsson
# henrik.olsson@fireeye.com
#
# For license information see the 'LICENSE' file
##################################################

# Core python imports
import base64
import sys
import logging
import json
import io
import os
import datetime
import time
import signal
import xml.etree.ElementTree as ET
from string import Template
from xml.sax.saxutils import escape as xmlescape
import re
from io import BytesIO

# Flask imports
try:
	from flask import Flask, request, Response, session, redirect, render_template, send_file, g, url_for, abort, Blueprint
	from jinja2 import evalcontextfilter, Markup, escape
except ImportError:
	print("hxtool requires the 'Flask' module, please install it.")
	exit(1)
	
# hx_tool imports
import hxtool_global
from hx_lib import *
from hxtool_util import *
from hxtool_formatting import *
from hxtool_db import *
from hxtool_config import *
from hxtool_data_models import *
from hxtool_session import *
from hxtool_scheduler import *
from hxtool_task_modules import *


# Import HXTool API Flask blueprint
from hxtool_api import ht_api

app = Flask(__name__, static_url_path='/static')

# Register HXTool API blueprint
app.register_blueprint(ht_api)

HXTOOL_API_VERSION = 1
default_encoding = 'utf-8'

### Flask/Jinja Filters
####################################

_newline_re = re.compile(r'(?:\r\n|\r|\n){1,}')
@app.template_filter()
@evalcontextfilter
def nl2br(eval_ctx, value):
	result = '<br />\n'.join(escape(p) for p in _newline_re.split(value or ''))
	if eval_ctx.autoescape:
		result = Markup(result)
	return result

### Dashboard page
@app.route('/', methods=['GET'])
@valid_session_required
def dashboard(hx_api_object):
	return render_template('ht_dashboard.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### AV Dashboard
@app.route('/dashboard-av', methods=['GET'])
@valid_session_required
def dashboardav(hx_api_object):
	return render_template('ht_dashboard-av.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Alerts page
@app.route('/alert', methods=['GET'])
@valid_session_required
def alert(hx_api_object):
	return render_template('ht_alert.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Scheduler page
@app.route('/scheduler', methods=['GET'])
@valid_session_required
def scheduler_view(hx_api_object):
	return render_template('ht_scheduler.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Script builder page
@app.route('/scriptbuilder', methods=['GET', 'POST'])
@valid_session_required
def scriptbuilder_view(hx_api_object):
	if request.method == 'POST':
		
		mydata = request.get_json(silent=True)

		app.hxtool_db.scriptCreate(mydata['scriptName'], HXAPI.b64(json.dumps(mydata['script'], indent=4).encode()), session['ht_user'])
		return(app.response_class(response=json.dumps("OK"), status=200, mimetype='application/json'))
	else:
		myauditspacefile = open(combine_app_path('static/acquisitions.json'), 'r')
		auditspace = myauditspacefile.read()
		myauditspacefile.close()
		return render_template('ht_scriptbuilder.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), auditspace=auditspace)


### Task profile page
@app.route('/taskprofile', methods=['GET', 'POST'])
@valid_session_required
def taskprofile(hx_api_object):

	if request.args.get('action'):
		if request.args.get('action') == "delete":
			app.hxtool_db.taskProfileDelete(request.args.get('id'))
			return redirect("/taskprofile", code=302)

	if request.method == 'POST':

		mydata = []
		params = {}

		for sfield, svalue in request.form.items():

			if sfield == "taskprofile_name":
				profilename = svalue
			elif sfield == "module":
				continue
			else:
				myfieldlist = sfield.split("_")

				if not myfieldlist[0] in params.keys():
					params[myfieldlist[0]] = {}

				params[myfieldlist[0]][myfieldlist[2]] = svalue

		for mykey, myval in params.items():
			if 'tablename' in myval.keys():
				myval.update({"module": "db"})
				mydata.append(myval)
			elif 'targetip' in myval.keys():
				myval.update({"module": "ip"})
				mydata.append(myval)
			elif 'filepath' in myval.keys():
				myval.update({"module": "file"})
				mydata.append(myval)

		app.hxtool_db.taskProfileAdd(profilename, session['ht_user'], mydata)

		return redirect("/taskprofile", code=302)
	else:
		return render_template('ht_taskprofile.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))


### Bulk acq page
@app.route('/bulkacq', methods=['GET', 'POST'])
@valid_session_required
def bulkacq_view(hx_api_object):

	if request.method == 'POST':
		start_time = None
		interval = None
		
		if 'schedule' in request.form.keys():
			if request.form['schedule'] == 'run_at':
				start_time = HXAPI.dt_from_str(request.form['scheduled_timestamp'])
				
			if request.form['schedule'] == 'run_interval':
				start_time, interval = hxtool_global.hxtool_scheduler.schedule_from_interval(minutes = request.form.get('intervalMin', 0),
																							hours = request.form.get('intervalHour', 0),
																							weekday = request.form.get('intervalWeek', None),
																							weeks = 1,
																							months = request.form.get('intervalDay', 0))

		bulk_acquisition_script = None
		skip_base64 = False
		should_download = False
		
		if 'file' in request.form.keys():
			f = request.files['bulkscript']
			bulk_acquisition_script = f.read()
		elif 'store' in request.form.keys():
			bulk_acquisition_script = app.hxtool_db.scriptGet(request.form['script'])['script']
			skip_base64 = True
		
		task_profile = None
		if request.form.get('taskprocessor', False):
			task_profile = request.form.get('taskprofile_id', None)
			should_download = True
			
		submit_bulk_job(hx_api_object, 
						int(request.form['bulkhostset']), 
						bulk_acquisition_script, 
						start_time = start_time, 
						interval = interval, 
						task_profile = task_profile, 
						download = should_download,
						skip_base64 = skip_base64,
						comment=request.form['bulkcomment'])
		app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		
		return redirect("/bulkacq", code=302)
	else:
		(ret, response_code, response_data) = hx_api_object.restListHostsets()
		hostsets = formatHostsets(response_data)

		myscripts = app.hxtool_db.scriptList()
		scripts = formatScripts(myscripts)

		mytaskprofiles = app.hxtool_db.taskProfileList()
		taskprofiles = formatTaskprofiles(mytaskprofiles)

	return render_template('ht_bulkacq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostsets=hostsets, scripts=scripts, taskprofiles=taskprofiles)


### Hosts
##########

@app.route('/hosts', methods=['GET', 'POST'])
@valid_session_required
def hosts(hx_api_object):
	# Host investigation panel
	if 'host' in request.args.keys():
		(ret, response_code, response_data) = hx_api_object.restGetHostSummary(request.args.get('host'))
		myhosthtml = formatHostInfo(response_data, hx_api_object)
		return render_template('ht_hostinfo.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostinfo=myhosthtml)
	
	# Host search returns table of hosts
	elif 'q' in request.args.keys():
		(ret, response_code, response_data) = hx_api_object.restListHosts(search_term = request.args.get('q'))
		myhostlist = formatHostSearch(response_data, hx_api_object)
		return render_template('ht_hostsearch.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), myhostlist=myhostlist)
		
	# Contain a host
	elif 'contain' in request.args.keys():
		(ret, response_code, response_data) = hx_api_object.restRequestContainment(request.args.get('contain'))
		if ret:
			app.logger.info('Containment request issued - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('contain'))
			(ret, response_code, response_data) = hx_api_object.restApproveContainment(request.args.get('contain'))
			if ret:
				app.logger.info('Containment request approved - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('contain'))
		return redirect(request.args.get('url'), code=302)
	
	# Uncontain a host
	elif 'uncontain' in request.args.keys():
		(ret, response_code, response_data) = hx_api_object.restRemoveContainment(request.args.get('uncontain'))
		if ret:
			app.logger.info('Uncontained issued - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('uncontain'))
		return redirect(request.args.get('url'), code=302)
	
	# Approve containment
	elif 'appcontain' in request.args.keys():
		(ret, response_code, response_data) = hx_api_object.restApproveContainment(request.args.get('appcontain'))
		if ret:
			app.logger.info('Containment approval - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('appcontain'))
		return redirect(request.args.get('url'), code=302)
		
	# Requests triage
	elif 'triage' in request.args.keys():
	
		# Standard triage
		if request.args.get('type') == "standard":
			(ret, response_code, response_data) = hx_api_object.restAcquireTriage(request.args.get('triage'))
			if ret:
				app.logger.info('Standard Triage requested - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('triage'))
		
		# Triage with predetermined time
		elif request.args.get('type') in ("1", "2", "4", "8"):
				mytime = datetime.datetime.now() - timedelta(hours = int(request.args.get('type')))
				(ret, response_code, response_data) = hx_api_object.restAcquireTriage(request.args.get('triage'), mytime.strftime('%Y-%m-%d %H:%M:%S'))
				if ret:
					app.logger.info('Triage requested around timestamp - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('triage'))
		
		# Triage with custom timestamp
		elif request.args.get('type') == "timestamp":
			(ret, response_code, response_data) = hx_api_object.restAcquireTriage(request.args.get('triage'), request.args.get('timestampvalue'))
			if ret:
				app.logger.info('Triage requested around timestamp - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('triage'))
			
		return redirect(request.args.get('url'), code=302)
		
	# File acquisition request
	elif 'fileaq' in request.args.keys():
		if request.args.get('type') and request.args.get('filepath') and request.args.get('filename'):
			
			if request.args.get('type') == "API":
				mode = True
			if request.args.get('type') == "RAW":
				mode = False
				
			(ret, response_code, response_data) = hx_api_object.restAcquireFile(request.args.get('fileaq'), request.args.get('filepath'), request.args.get('filename'), mode)
			if ret:
				app.logger.info('File acquisition requested - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('fileaq'))
			
		return redirect(request.args.get('url'), code=302)
	elif 'acq' in request.form.keys():

		fc = request.files['script']				
		myscript = fc.read()
		
		(ret, response_code, response_data) = hx_api_object.restNewAcquisition(request.form.get('acq'), request.form.get('name'), myscript)
		if ret:
			app.logger.info('Data acquisition requested - User: %s@%s:%s - host: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('acq'))

		return redirect(request.form.get('url'), code=302)
	else:
		return redirect('/', code=302)
			

### Triage popup
@app.route('/triage', methods=['GET'])
@valid_session_required
def triage(hx_api_object):
	triageid= request.args.get('host')
	url = request.args.get('url')
	mytime = datetime.datetime.now()
	return render_template('ht_triage.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), triageid=triageid, url=url, now=mytime.strftime('%Y-%m-%d %H:%M:%S'))

		
### File acquisition popup
@app.route('/fileaq', methods=['GET'])
@valid_session_required
def fileaq(hx_api_object):
	hostid = request.args.get('host')
	url = request.args.get('url')
	return render_template('ht_fileaq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostid=hostid, url=url)

		
### Acquisition popup
@app.route('/acq', methods=['GET'])
@valid_session_required
def acq(hx_api_object):
	hostid = request.args.get('host')
	url = request.args.get('url')
	return render_template('ht_acq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostid=hostid, url=url)
		
### Annotations
@app.route('/annotateadd', methods=['POST'])
@valid_session_required
def annotateadd(hx_api_object):
	if request.method == "POST" and 'annotateText' in request.form:
		app.hxtool_db.alertCreate(session['ht_profileid'], request.form['annotationBoxID'])
		app.hxtool_db.alertAddAnnotation(session['ht_profileid'], request.form['annotationBoxID'], request.form['annotateText'], request.form['annotateState'], session['ht_user'])
		app.logger.info('New annotation - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return('', 204)
	else:
		return('', 500)
		
@app.route('/annotatedisplay', methods=['GET'])
@valid_session_required
def annotatedisplay(hx_api_object):	
	if 'alertid' in request.args:
		alert = app.hxtool_db.alertGet(session['ht_profileid'], request.args.get('alertid'))
		an = None
		if alert:
			an = alert['annotations']
		annotatetable = formatAnnotationTable(an)

	return render_template('ht_annotatedisplay.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), annotatetable=annotatetable)

### Acquisitions listing
@app.route('/acqs', methods=['GET'])
@valid_session_required
def acqs(hx_api_object):
	return render_template('ht_acqs.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

#### Enterprise Search
@app.route('/search', methods=['GET', 'POST'])
@valid_session_required
def search(hx_api_object):	
	# If we get a post it's a new sweep
	if request.method == 'POST':
		if 'file' in request.form.keys():
			f = request.files['newioc']
			ioc_script = HXAPI.b64(f.read())
		elif 'store' in request.form.keys():
			ioc_script = app.hxtool_db.oiocGet(request.form['ioc'])['ioc']
		
		ignore_unsupported_items = False
		if 'esskipterms' in request.form.keys():
			ignore_unsupported_items = (request.form['esskipterms'] == 'true')

		enterprise_search_task = hxtool_scheduler_task(session['ht_profileid'], "Enterprise Search Task")
		enterprise_search_task.add_step(enterprise_search_task_module, kwargs = {
											'script' : ioc_script,
											'hostset_id' : request.form['sweephostset'],
											'ignore_unsupported_items' : ignore_unsupported_items,
											'skip_base64': True
										})
		hxtool_global.hxtool_scheduler.add(enterprise_search_task)
		app.logger.info('New Enterprise Search - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/search", code=302)
	else:
		(ret, response_code, response_data) = hx_api_object.restListHostsets()
		hostsets = formatHostsets(response_data)

		myiocs = app.hxtool_db.oiocList()
		openiocs = formatOpenIocs(myiocs)
		
		return render_template('ht_searchsweep.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostsets=hostsets, openiocs=openiocs)

@app.route('/searchresult', methods=['GET'])
@valid_session_required
def searchresult(hx_api_object):
	if request.args.get('id'):
		(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'))
		return render_template('ht_search_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
			
@app.route('/searchaction', methods=['GET'])
@valid_session_required
def searchaction(hx_api_object):
	if request.args.get('action') == "stop":
		(ret, response_code, response_data) = hx_api_object.restCancelJob('searches', request.args.get('id'))
		app.logger.info('User access: Enterprise Search action STOP - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/search", code=302)

	if request.args.get('action') == "remove":
		(ret, response_code, response_data) = hx_api_object.restDeleteJob('searches', request.args.get('id'))
		app.logger.info('User access: Enterprise Search action REMOVE - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/search", code=302)

### Manage Indicators
#########################

@app.route('/indicators', methods=['GET', 'POST'])
@valid_session_required
def indicators(hx_api_object):
	if request.method == 'POST':
		
		# Export selected indicators
		iocs = []
		for postvalue in request.form:
			if postvalue.startswith('ioc___'):
				sval = postvalue.split("___")
				iocname = sval[1]
				ioccategory = sval[2]
				platforms = sval[3]
				iocs.append({'uuid':request.form.get(postvalue), 'name':iocname, 'category':ioccategory, 'platforms':platforms})
		
		ioclist = {}
		for ioc in iocs:
			#Data structure for the conditions
			ioclist[ioc['uuid']] = {}
			ioclist[ioc['uuid']]['execution'] = []
			ioclist[ioc['uuid']]['presence'] = []
			ioclist[ioc['uuid']]['name'] = ioc['name']
			ioclist[ioc['uuid']]['category'] = ioc['category']
			ioclist[ioc['uuid']]['platforms'] = ioc['platforms'].split(',')

			#Grab execution indicators
			(ret, response_code, response_data) = hx_api_object.restGetCondition(ioc['category'], ioc['uuid'], 'execution')
			for item in response_data['data']['entries']:
				ioclist[ioc['uuid']]['execution'].append(item['tests'])

			#Grab presence indicators
			(ret, response_code, response_data) = hx_api_object.restGetCondition(ioc['category'], ioc['uuid'], 'presence')
			for item in response_data['data']['entries']:
				ioclist[ioc['uuid']]['presence'].append(item['tests'])
							
		if len(iocs) == 1:
			iocfname = iocs[0]['name'] + ".ioc"
		else:
			iocfname = "multiple_indicators.ioc"
		
		
		
		buffer = BytesIO()
		buffer.write(json.dumps(ioclist, indent=4, ensure_ascii=False).encode(default_encoding))
		buffer.seek(0)
		app.logger.info('Indicator(s) exported - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return send_file(buffer, attachment_filename=iocfname, as_attachment=True)

	(ret, response_code, response_data) = hx_api_object.restListCategories()
	if ret:
		mycategories = {}
		for category in response_data['data']['entries']:
			mycategories[category['_id']] = category['ui_edit_policy']

	(ret, response_code, response_data) = hx_api_object.restListIndicators()
	indicators = formatIOCResults(response_data, mycategories)
	return render_template('ht_indicators.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), indicators=indicators)

@app.route('/indicatorcondition', methods=['GET'])
@valid_session_required
def indicatorcondition(hx_api_object):
	uuid = request.args.get('uuid')

	(ret, response_code, response_data) = hx_api_object.restListIndicators(limit=1, filter_term={ "uri_name": uuid })
	category = response_data['data']['entries'][0]['category']['uri_name']

	(ret, response_code, condition_class_presence) = hx_api_object.restGetCondition(category, uuid, 'presence')
	(ret, response_code, condition_class_execution) = hx_api_object.restGetCondition(category, uuid, 'execution')
	
	conditions = formatConditions(condition_class_presence, condition_class_execution)

	return render_template('ht_indicatorcondition.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), conditions=conditions)

		

@app.route('/categories', methods=['GET', 'POST'])
@valid_session_required
def categories(hx_api_object):
	if request.method == 'POST':
		catname = request.form.get('catname')

		(ret, response_code, response_data) = hx_api_object.restCreateCategory(HXAPI.compat_str(catname), category_options={"ui_edit_policy": HXAPI.compat_str(request.form.get('editpolicy')), "retention_policy": HXAPI.compat_str(request.form.get('retentionpolicy'))})
		if ret:
			app.logger.info('New indicator category created - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)


	(ret, response_code, response_data) = hx_api_object.restListCategories()
	categories = formatCategories(response_data)
	
	return render_template('ht_categories.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), categories=categories)

@app.route('/import', methods=['POST'])
@valid_session_required
def importioc(hx_api_object):
	if request.method == 'POST':
	
		fc = request.files['iocfile']				
		iocs = json.loads(fc.read().decode(default_encoding))
		
		for iockey in iocs:

			# Check if category exists
			category_exists = False
			(ret, response_code, response_data) = hx_api_object.restListCategories(limit = 1, filter_term={'name' : iocs[iockey]['category']})
			if ret:
				# As it turns out, filtering by name also returns partial matches. However the exact match seems to be the 1st result
				category_exists = (len(response_data['data']['entries']) == 1 and response_data['data']['entries'][0]['name'].lower() == iocs[iockey]['category'].lower())
				if not category_exists:
					app.logger.info('Adding new IOC category as part of import: %s - User: %s@%s:%s', iocs[iockey]['category'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
					(ret, response_code, response_data) = hx_api_object.restCreateCategory(HXAPI.compat_str(iocs[iockey]['category']))
					category_exists = ret
				
				if category_exists:
					(ret, response_code, response_data) = hx_api_object.restAddIndicator(iocs[iockey]['category'], iocs[iockey]['name'], session['ht_user'], iocs[iockey]['platforms'])
					if ret:
						ioc_guid = response_data['data']['_id']
						
						for p_cond in iocs[iockey]['presence']:
							data = json.dumps(p_cond)
							data = """{"tests":""" + data + """}"""
							(ret, response_code, response_data) = hx_api_object.restAddCondition(iocs[iockey]['category'], ioc_guid, 'presence', data)

						for e_cond in iocs[iockey]['execution']:
							data = json.dumps(e_cond)
							data = """{"tests":""" + data + """}"""
							(ret, response_code, response_data) = hx_api_object.restAddCondition(iocs[iockey]['category'], ioc_guid, 'execution', data)
				
						app.logger.info('New indicator imported - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				else:
					app.logger.warn('Unable to create category for indicator import - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			else:
				app.logger.warn('Unable to import indicator - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	
	return redirect("/indicators", code=302)

### Real-time indicators
@app.route('/rtioc', methods=['POST', 'GET'])
@valid_session_required
def rtioc(hx_api_object):

		# New indicator mode
		if request.method == 'GET':
			
			myEventFile = open(combine_app_path('static/eventbuffer.json'), 'r')
			eventspace = myEventFile.read()
			myEventFile.close()

			if request.args.get('indicator'):

				uuid = request.args.get('indicator')

				(ret, response_code, response_data) = hx_api_object.restListCategories()
				categories = formatCategoriesSelect(response_data)

				(ret, response_code, response_data) = hx_api_object.restListIndicators(limit=1, filter_term={ 'uri_name': uuid })
				if ret:
					iocname = response_data['data']['entries'][0]['name']
					myiocuri = response_data['data']['entries'][0]['uri_name']
					ioccategory = response_data['data']['entries'][0]['category']['uri_name']
					mydescription = response_data['data']['entries'][0]['description']
					if len(response_data['data']['entries'][0]['platforms']) == 1:
						platform = response_data['data']['entries'][0]['platforms'][0]
					else:
						platform = "all"

					(ret, response_code, condition_class_presence) = hx_api_object.restGetCondition(ioccategory, uuid, 'presence')
					(ret, response_code, condition_class_execution) = hx_api_object.restGetCondition(ioccategory, uuid, 'execution')

					mypre = json.dumps(condition_class_presence['data']['entries'])
					myexec = json.dumps(condition_class_execution['data']['entries'])

					if request.args.get('clone'):
						ioccategory = "Custom"

				return render_template('ht_indicator_create_edit.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), categories=categories, iocname=iocname, myiocuri=myiocuri, myioccategory=ioccategory, mydescription=mydescription, ioccategory=json.dumps(ioccategory), platform=json.dumps(platform), mypre=mypre, myexec=myexec, eventspace=eventspace)
			elif request.args.get('delete'):
				(ret, response_code, response_data) = hx_api_object.restDeleteIndicator(request.args.get('category'), request.args.get('delete'))
				if ret:
					return redirect("/indicators", code=302)
			else:
				(ret, response_code, response_data) = hx_api_object.restListCategories()
				categories = formatCategoriesSelect(response_data)
				return render_template('ht_indicator_create_edit.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), categories=categories, eventspace=eventspace)

		# New indicator created or edit mode engaged!		
		elif request.method == 'POST':
			mydata = request.get_json(silent=True)

			# New indicator to be created (new mode)
			if (request.args.get('mode') == "new"):

				if mydata['platform'] == "all":
					chosenplatform = ['win', 'osx']
				else:
					chosenplatform = [mydata['platform']]

				(ret, response_code, response_data) = hx_api_object.restAddIndicator(mydata['category'], mydata['name'], session['ht_user'], chosenplatform, description=mydata['description'])
				if ret:
					ioc_guid = response_data['data']['_id']

					for key, value in mydata.items():
						if key not in ['name', 'category', 'platform', 'description']:
							(iocguid, ioctype) = key.split("_")
							mytests = {"tests": []}
							for entry in value:
								if not entry['negate'] and not entry['case']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data']})
								elif entry['negate'] and not entry['case']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "negate": True})
								elif entry['case'] and not entry['negate']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "preservecase": True})
								else:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "negate": True, "preservecase": True})

							(ret, response_code, response_data) = hx_api_object.restAddCondition(mydata['category'], ioc_guid, ioctype, json.dumps(mytests))
							if not ret:
								# Remove the indicator if condition push was unsuccessful
								(ret, response_code, response_data) = hx_api_object.restDeleteIndicator(mydata['category'], ioc_guid)
								return ('', 500)
					# All OK
					return ('', 204)
				else:
					# Failed to create indicator
					return ('', 500)

			# Edit indicator
			elif (request.args.get('mode') == "edit"):

				# Get the original URI
				myOriginalURI = mydata['iocuri']
				myOriginalCategory = mydata['originalcategory']
				myState = True

				if mydata['platform'] == "all":
					chosenplatform = ['win', 'osx']
				else:
					chosenplatform = [mydata['platform']]

				(ret, response_code, response_data) = hx_api_object.restAddIndicator(mydata['category'], mydata['name'], session['ht_user'], chosenplatform, description=mydata['description'])
				if ret:
					myNewURI = response_data['data']['_id']
					for key, value in mydata.items():
						if key not in ['name', 'category', 'platform', 'originalname', 'originalcategory', 'iocuri', 'description']:
							(iocguid, ioctype) = key.split("_")
							mytests = {"tests": []}
							for entry in value:
								if not entry['negate'] and not entry['case']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data']})
								elif entry['negate'] and not entry['case']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "negate": True})
								elif entry['case'] and not entry['negate']:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "preservecase": True})
								else:
									mytests['tests'].append({"token": entry['group'] + "/" + entry['field'], "type": entry['type'], "operator": entry['operator'], "value": entry['data'], "negate": True, "preservecase": True})

							(ret, response_code, response_data) = hx_api_object.restAddCondition(mydata['category'], myNewURI, ioctype, json.dumps(mytests))
							if not ret:
								# Condition was not added successfully set state to False to prevent the original indicator from being removed
								myState = False
								return('', 500)
					# Everything is OK
					if myState:
						# Remove the original indicator
						(ret, response_code, response_data) = hx_api_object.restDeleteIndicator(myOriginalCategory, myOriginalURI)
					return('', 204)
				else:
					# Failed to create indicator
					return('',500)
			else:
				# Invalid request
				return('', 500)

### Bulk Acquisition
@app.route('/bulk', methods=['GET', 'POST'])
@valid_session_required
def listbulk(hx_api_object):
	if request.method == 'POST':
		if 'file' in request.form.keys():
			f = request.files['bulkscript']
			bulk_acquisition_script = f.read()
			submit_bulk_job(hx_api_object, int(request.form['bulkhostset']), bulk_acquisition_script, download = False)
			app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		elif 'store' in request.form.keys():
			scriptdef = app.hxtool_db.scriptGet(request.form['script'])
			submit_bulk_job(hx_api_object, int(request.form['bulkhostset']), scriptdef['script'], download = False, skip_base64 = True)
			app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
	else:
		(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
		bulktable = formatBulkTable(app.hxtool_db, response_data, session['ht_profileid'])
		
		(ret, response_code, response_data) = hx_api_object.restListHostsets()
		hostsets = formatHostsets(response_data)

		myscripts = app.hxtool_db.scriptList()
		scripts = formatScripts(myscripts)

		return render_template('ht_bulk.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable, hostsets=hostsets, scripts=scripts)
	
@app.route('/bulkdetails', methods = ['GET'])
@valid_session_required
def bulkdetails(hx_api_object):
	if request.args.get('id'):

		(ret, response_code, response_data) = hx_api_object.restListBulkHosts(request.args.get('id'))
		if ret:
			bulktable = formatBulkHostsTable(response_data)
		else:
			abort(Response("Failed to retrieve bulk acquisition details from the controller, response code: {}, response data: {}".format(response_code, response_data)))
		return render_template('ht_bulk_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable)
	else:
		abort(404)


# TODO: These two functions should be merged at some point
@app.route('/bulkdownload', methods = ['GET'])
@valid_session_required
def bulkdownload(hx_api_object):
	if request.args.get('id'):
		(ret, response_code, response_data) = hx_api_object.restDownloadFile(request.args.get('id'))
		if ret:
			app.logger.info('Bulk acquisition download - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('id'))
			flask_response = Response(iter_chunk(response_data))
			flask_response.headers['Content-Type'] = response_data.headers['Content-Type']
			flask_response.headers['Content-Disposition'] = response_data.headers['Content-Disposition']
			return flask_response
		else:
			return "HX controller responded with code {0}: {1}".format(response_code, response_data)
	else:
		abort(404)

		
@app.route('/download')
@valid_session_required
def download(hx_api_object):
	if request.args.get('id'):
		if request.args.get('content') == "json":
			(ret, response_code, response_data) = hx_api_object.restDownloadFile(request.args.get('id'), accept = "application/json")
		else:
			(ret, response_code, response_data) = hx_api_object.restDownloadFile(request.args.get('id'))
		if ret:
			app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('id'))
			flask_response = Response(iter_chunk(response_data))
			flask_response.headers['Content-Type'] = response_data.headers['Content-Type']
			flask_response.headers['Content-Disposition'] = response_data.headers['Content-Disposition']
			return flask_response
		else:
			return "HX controller responded with code {0}: {1}".format(response_code, response_data)
	else:
		abort(404)		

@app.route('/download_file')
@valid_session_required
def download_multi_file_single(hx_api_object):
	if 'mf_id' in request.args and 'acq_id' in request.args:
		multi_file = app.hxtool_db.multiFileGetById(request.args.get('mf_id'))
		if multi_file:
			file_records = list(filter(lambda f: int(f['acquisition_id']) == int(request.args.get('acq_id')), multi_file['files']))
			if file_records and file_records[0]:
				# TODO: should multi_file be hardcoded?
				path = combine_app_path(download_directory_base(), hx_api_object.hx_host, 'multi_file', request.args.get('mf_id'), '{}_{}.zip'.format(file_records[0]['hostname'], request.args.get('acq_id')))
				app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('acq_id'))
				return send_file(path, attachment_filename=os.path.basename(path), as_attachment=True)
		else:
			return "HX controller responded with code {0}: {1}".format(response_code, response_data)
	abort(404)		

@app.route('/bulkaction', methods=['GET'])
@valid_session_required
def bulkaction(hx_api_object):

	if request.args.get('action') == "stop":
		(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', request.args.get('id'))
		app.logger.info('Bulk acquisition action STOP - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulkacq", code=302)
		
	if request.args.get('action') == "remove":
		(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', request.args.get('id'))
		app.logger.info('Bulk acquisition action REMOVE - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulkacq", code=302)	
		
	if request.args.get('action') == "download":
		(ret, response_code, response_data) = hx_api_object.restListBulkHosts(request.args.get('id'))
		
		if ret and response_data and len(response_data['data']['entries']) > 0:
			bulk_acquisition_hosts = {}
			task_list = []
			for host in response_data['data']['entries']:
				bulk_acquisition_hosts[host['host']['_id']] = {'downloaded' : False, 'hostname' :  host['host']['hostname']}
				bulk_acquisition_download_task = hxtool_scheduler_task(session['ht_profileid'], 'Bulk Acquisition Download: {}'.format(host['host']['hostname']))
				bulk_acquisition_download_task.add_step(bulk_download_task_module, kwargs = {
															'bulk_acquisition_id' : request.args.get('id'),
															'host_id' : host['host']['_id'],
															'host_name' : host['host']['hostname']
														})
				# This works around a nasty race condition where the task would start before the download job was added to the database				
				task_list.append(bulk_acquisition_download_task)
		
			hostset_id = -1
			(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(request.args.get('id'))
			if ret:
				if 'host_set' in response_data['data']:
					hostset_id = int(response_data['data']['host_set']['_id'])
			
			app.hxtool_db.bulkDownloadCreate(session['ht_profileid'], request.args.get('id'), bulk_acquisition_hosts, hostset_id = hostset_id)	
		
			hxtool_global.hxtool_scheduler.add_list(task_list)
			
			app.logger.info('Bulk acquisition action DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		else:
			app.logger.warn("No host entries were returned for bulk acquisition: {}. Did you just start the job? If so, wait for the hosts to be queued up.".format(request.args.get('id')))
		return redirect("/bulkacq", code=302)
		
	if request.args.get('action') == "stopdownload":
		ret = app.hxtool_db.bulkDownloadUpdate(request.args.get('id'), stopped = True)
		# TODO: don't delete the job because the task module needs to know if the job is stopped or not.
		#ret = app.hxtool_db.bulkDownloadDelete(session['ht_profileid'], request.args.get('id'))
		app.logger.info('Bulk acquisition action STOP DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulkacq", code=302)

### Scripts
@app.route('/scripts', methods=['GET', 'POST'])
@valid_session_required
def scripts(hx_api_object):
	if request.method == "POST":
		fc = request.files['script']				
		rawscript = fc.read()
		app.hxtool_db.scriptCreate(request.form['scriptname'], HXAPI.b64(rawscript), session['ht_user'])
		return redirect("/scripts", code=302)
	elif request.method == "GET":
		if request.args.get('action'):
			if request.args.get('action') == "delete":
				app.hxtool_db.scriptDelete(request.args.get('id'))
				return redirect("/scripts", code=302)
			elif request.args.get('action') == "view":
				storedscript = app.hxtool_db.scriptGet(request.args.get('id'))
				return render_template('ht_scripts_view.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), script=HXAPI.b64(storedscript['script'], decode=True, decode_string=True))
			else:
				return render_template('ht_scripts.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
		else:
			return render_template('ht_scripts.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### OpenIOCs
@app.route('/openioc', methods=['GET', 'POST'])
@valid_session_required
def openioc(hx_api_object):
	if request.method == "POST":
		fc = request.files['ioc']				
		rawioc = fc.read()
		app.hxtool_db.oiocCreate(request.form['iocname'], HXAPI.b64(rawioc), session['ht_user'])
		return redirect("/openioc", code=302)
	elif request.method == "GET":
		if request.args.get('action'):
			if request.args.get('action') == "delete":
				app.hxtool_db.oiocDelete(request.args.get('id'))
				return redirect("/openioc", code=302)
			elif request.args.get('action') == "view":
				storedioc = app.hxtool_db.oiocGet(request.args.get('id'))
				return render_template('ht_openioc_view.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), ioc=HXAPI.b64(storedioc['ioc'], decode=True, decode_string=True))
			else:
				return render_template('ht_openioc.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
		else:
			return render_template('ht_openioc.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Multifile acquisitions
@app.route('/multifile', methods=['GET', 'POST'])
@valid_session_required
def multifile(hx_api_object):
	profile_id = session['ht_profileid']
	if request.args.get('stop'):
		mf_job = app.hxtool_db.multiFileGetById(request.args.get('stop'))
		if mf_job:
			success = True
			#TODO: Stop each file acquisition or handle solely in remove?
			if success:
				app.hxtool_db.multiFileStop(mf_job.eid)
				app.logger.info('MultiFile Job ID {0} action STOP - User: {1}@{2}:{3}'.format(mf_job.eid, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))

	elif request.args.get('remove'):
		mf_job = app.hxtool_db.multiFileGetById(request.args.get('remove'))
		if mf_job:
			success = True
			for f in mf_job['files']:
				uri = 'acqs/files/{0}'.format(f['acquisition_id'])
				(ret, response_code, response_data) = hx_api_object.restDeleteFile(uri)
				#TODO: Replace with delete of file from record
				if not f['downloaded']:
					app.hxtool_db.multiFileUpdateFile(profile_id, mf_job.eid, f['acquisition_id'])
				# If the file acquisition no longer exists on the controller(404), then we should delete it from our DB anyway.
				if not ret and response_code != 404:
					app.logger.error("Failed to remove file acquisition {0} from the HX controller, response code: {1}".format(f['acquisition_id'], response_code))
					success = False		
			if success:
				app.hxtool_db.multiFileDelete(mf_job.eid)
				app.logger.info('MultiFile Job ID {0} action REMOVE - User: {1}@{2}:{3}'.format( mf_job.eid, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))

	#TODO: Make Configurable both from GUI and config file?
	elif request.method == 'POST':
		MAX_FILE_ACQUISITIONS = 50
		
		display_name = ('display_name' in request.form) and request.form['display_name'] or "{0} job at {1}".format(session['ht_user'], datetime.datetime.now())
		use_api_mode = ('use_raw_mode' not in request.form)

		# Collect User Selections
		file_jobs, choices, listing_ids = [], {}, set([])
		choice_re = re.compile('^choose_file_(\d+)_(\d+)$')
		for k, v in list(request.form.items()):
			m = choice_re.match(k)
			if m:
				fl_id = int(m.group(1))
				listing_ids.add(fl_id)
				choices.setdefault(fl_id, []).append(int(m.group(2)))
		if choices:
			choice_files, agent_ids = [], {}
			for fl_id, file_ids in list(choices.items()):
				# Gather the records for files to acquire from the file listing
				file_listing = app.hxtool_db.fileListingGetById(fl_id)
				if not file_listing:
					app.logger.warn('File Listing %s does not exist - User: %s@%s:%s', session['ht_user'], fl_id, hx_api_object.hx_host, hx_api_object.hx_port)
					continue
				choice_files = [file_listing['files'][i] for i in file_ids if i <= len(file_listing['files'])]
				multi_file_eid = app.hxtool_db.multiFileCreate(session['ht_user'], profile_id, display_name=display_name, file_listing_id=file_listing.eid, api_mode=use_api_mode)
				# Create a data acquisition for each file from its host
				for cf in choice_files:
					if cf['hostname'] in agent_ids:
						agent_id = agent_ids[cf['hostname']]
					else:
						(ret, response_code, response_data) = hx_api_object.restListHosts(search_term = cf['hostname'])
						agent_id = agent_ids[cf['hostname']] = response_data['data']['entries'][0]['_id']
					path, filename = cf['FullPath'].rsplit('\\', 1)
					(ret, response_code, response_data) = hx_api_object.restAcquireFile(agent_id, path, filename, use_api_mode)
					if ret:
						acq_id = response_data['data']['_id']
						job_record = {
							'acquisition_id' : int(acq_id),
							'hostname': cf['hostname'],
							'path': cf['FullPath'],
							'downloaded': False
						}
						mf_job_id = app.hxtool_db.multiFileAddJob(multi_file_eid, job_record)
						file_acquisition_task = hxtool_scheduler_task(profile_id, "File Acquisition: {}".format(cf['hostname']))
						file_acquisition_task.add_step(file_acquisition_task_module, kwargs = {
															'multi_file_eid' : multi_file_eid,
															'file_acquisition_id' : int(acq_id),
															'host_name' : cf['hostname']
														})
						hxtool_global.hxtool_scheduler.add(file_acquisition_task)
						app.logger.info('File acquisition requested from host %s at path %s- User: %s@%s:%s - host: %s', cf['hostname'], cf['FullPath'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, agent_id)
						file_jobs.append(acq_id)
						if len(file_jobs) >= MAX_FILE_ACQUISITIONS:
							break
					else:
						#TODO: Handle fail
						pass
			if file_jobs:
				app.logger.info('New Multi-File Download requested (profile %s) - User: %s@%s:%s', profile_id, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	return render_template('ht_multifile.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostsets=hostsets)

@app.route('/file_listing', methods=['GET', 'POST'])
@valid_session_required
def file_listing(hx_api_object):
	if request.args.get('stop'):
		file_listing_job = app.hxtool_db.fileListingGetById(request.args.get('stop'))
		if file_listing_job:
			bulk_download_job = app.hxtool_db.bulkDownloadGet(file_listing_job['bulk_download_eid'])
			(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])
			if ret:
				app.hxtool_db.fileListingStop(file_listing_job.eid)
				app.hxtool_db.bulkDownloadUpdate(file_listing_job['bulk_download_eid'], stopped = True)
				app.logger.info('File Listing ID {0} action STOP - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, file_listing_job.eid))
		return redirect("/multifile", code=302)

	elif request.args.get('remove'):
		file_listing_job = app.hxtool_db.fileListingGetById(request.args.get('remove'))
		if file_listing_job:
			bulk_download_job = app.hxtool_db.bulkDownloadGet(file_listing_job['bulk_download_eid'])
			if bulk_download_job.get('bulk_acquisition_id', None):
				(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])
			app.hxtool_db.bulkDownloadDelete(file_listing_job['bulk_download_eid'])
			app.hxtool_db.fileListingDelete(file_listing_job.eid)
			app.logger.info('File Listing ID {0} action REMOVE - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, file_listing_job.eid))
		return redirect("/multifile", code=302)

	elif request.method == 'POST':
		# Get Acquisition Options from Form
		display_name = xmlescape(request.form['listing_name'])
		regex = xmlescape(request.form['listing_regex'])
		path = xmlescape(request.form['listing_path'])
		hostset = int(xmlescape(request.form['hostset']))
		use_api_mode = ('use_raw_mode' not in request.form)
		depth = '-1'
		# Build a script from the template
		script_xml = None
		try:
			if regex:
				re.compile(regex)
			else:
				app.logger.warn("Regex is empty!!")
				regex = ''
			if use_api_mode:
				template_path = 'scripts/api_file_listing_script_template.xml'
			else:
				template_path = 'scripts/file_listing_script_template.xml'
			with open(combine_app_path(template_path), 'r') as f:
				t = Template(f.read())
				script_xml = t.substitute(regex=regex, path=path, depth=depth)
			if not display_name:
				display_name = 'hostset: {0} path: {1} regex: {2}'.format(hostset, path, regex)
		except re.error:
			#TODO: Handle invalid regex with response. (Inline AJAX?)
			raise
		if script_xml:
			bulk_download_eid = submit_bulk_job(hx_api_object, hostset, script_xml.encode(default_encoding), task_profile = "file_listing")
			ret = app.hxtool_db.fileListingCreate(session['ht_profileid'], session['ht_user'], bulk_download_eid, path, regex, depth, display_name, api_mode=use_api_mode)
			app.logger.info('New File Listing - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return redirect("/multifile", code=302)
		else:
			# TODO: Handle this condition 
			abort(404)

	#TODO: Modify template and move to Ajax
	fl_id = request.args.get('id')
	file_listing = app.hxtool_db.fileListingGetById(fl_id)
	fl_results = file_listing['files']
	display_fields = ['FullPath', 'Username', 'SizeInBytes', 'Modified', 'Sha256sum'] 

	return render_template('ht_file_listing.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), file_listing=file_listing, fl_results=fl_results, display_fields=display_fields)

@app.route('/_multi_files')
@valid_session_required
def get_multi_files(hx_api_object):
	profile_id = session['ht_profileid']
	data_rows = []
	for mf in app.hxtool_db.multiFileList(profile_id):
		job = dict(mf)
		hosts_completed = len([_ for _ in job['files'] if _['downloaded']])
		job.update({
			'id': mf.eid,
			'state': ("STOPPED" if job['stopped'] else "RUNNING"),
			'file_count': len(job['files']),
			'mode': ('api_mode' in job and job['api_mode']) and 'API' or 'RAW'
		})

		# Completion rate
		job_progress = (int(job['file_count']) > 0) and  int(hosts_completed / float(job['file_count']) * 100) or 0
		job['progress'] = "<div class='htMyBar htBarWrap'><div class='htBar' id='multi_file_prog_" + str(job['id']) + "' data-percent='" + str(job_progress) + "'></div></div>"
		
		# Actions
		job['actions'] = "<a href='/multifile?stop=" +  str(job['id']) + "' style='margin-right: 10px;' class='tableActionButton'>stop</a>"
		job['actions'] += "<a href='/multifile?remove=" +  str(job['id']) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		data_rows.append(job)
	return json.dumps({'data': data_rows})

@app.route('/_file_listings')
@valid_session_required
def get_file_listings(hx_api_object):
	profile_id = session['ht_profileid']
	data_rows = []
	for j in app.hxtool_db.fileListingList(profile_id):
		job = dict(j)
		job.update({'id': j.eid})
		job['state'] = ("STOPPED" if job['stopped'] else "RUNNING")
		job['file_count'] = len(job.pop('files'))

		# Completion rate
		bulk_download = app.hxtool_db.bulkDownloadGet(bulk_download_eid = job['bulk_download_eid'])
		if bulk_download:
			hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
			job_progress = int(hosts_completed / float(len(bulk_download['hosts'])) * 100)
			if 'display_name' not in job:
				job['display_name'] = 'hostset {0}, path: {1} regex: {2}'.format(bulk_download['hostset_id'] , job['cfg']['path'], job['cfg']['regex'])
		else:
			job_progress = job['file_count'] > 1 and 100 or 0
			if 'display_name' not in job:
				job['display_name'] = 'path: {0} regex: {1}'.format(job['cfg']['path'], job['cfg']['regex'])
		
		job['progress'] = "<div class='htMyBar htBarWrap'><div class='htBar' id='file_listing_prog_" + str(job['id']) + "' data-percent='" + str(job_progress) + "'></div></div>"
		
		# Actions
		job['actions'] = "<a href='/file_listing?stop=" +  str(job['id']) + "' style='margin-right: 10px;' class='tableActionButton'>stop</a>"
		job['actions'] += "<a href='/file_listing?remove=" +  str(job['id']) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		if job_progress > 0:
			job['actions'] += "<a href='/file_listing?id=" +  str(job['id']) + "' style='margin-right: 10px;' class='tableActionButton'>view</a>"
		data_rows.append(job)
	return json.dumps({'data': data_rows})

### Stacking
@app.route('/stacking', methods=['GET', 'POST'])
@valid_session_required
def stacking(hx_api_object):
	if request.args.get('stop'):
		stack_job = app.hxtool_db.stackJobGet(stack_job_eid = request.args.get('stop'))
		bulk_download_job = app.hxtool_db.bulkDownloadGet(bulk_download_eid = stack_job['bulk_download_eid'])
		if stack_job:
			
			(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])
			if ret:
				app.hxtool_db.stackJobStop(stack_job_eid = stack_job.eid)
				app.hxtool_db.bulkDownloadUpdate(bulk_download_job.eid, stopped = True)
				app.logger.info('Data stacking action STOP - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)

	if request.args.get('remove'):
		stack_job = app.hxtool_db.stackJobGet(request.args.get('remove'))
		if stack_job:
			bulk_download_job = app.hxtool_db.bulkDownloadGet(bulk_download_eid = stack_job['bulk_download_eid'])
			if bulk_download_job and 'bulk_acquisition_id' in bulk_download_job:
				(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])	
				app.hxtool_db.bulkDownloadDelete(bulk_download_job.eid)
				
			app.hxtool_db.stackJobDelete(stack_job.eid)
			app.logger.info('Data stacking action REMOVE - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)

		
	if request.method == 'POST':
		stack_type = hxtool_data_models.stack_types.get(request.form['stack_type'])
		if stack_type:
			with open(combine_app_path('scripts', stack_type['script']), 'r') as f:
				script_xml = f.read()
				hostset_id = int(request.form['stackhostset'])
				app.logger.info('Data stacking: New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				bulk_download_eid = submit_bulk_job(hx_api_object, hostset_id, script_xml, task_profile = "stacking")
				ret = app.hxtool_db.stackJobCreate(session['ht_profileid'], bulk_download_eid, request.form['stack_type'])
				app.logger.info('New data stacking job - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	stacktable = formatStackTable(app.hxtool_db, session['ht_profileid'], response_data)
	
	return render_template('ht_stacking.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable, hostsets=hostsets, stack_types = hxtool_data_models.stack_types)


@app.route('/stackinganalyze', methods=['GET', 'POST'])
@valid_session_required
def stackinganalyze(hx_api_object):
	return render_template('ht_stacking_analyze.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stack_id = request.args.get('id'))
		
			
### Settings
@app.route('/settings', methods=['GET', 'POST'])
@valid_session_required
def settings(hx_api_object):
	if request.method == 'POST':
		# Generate a new IV - must be 16 bytes
		iv = crypt_generate_random(16)
		salt = crypt_generate_random(32)
		key = crypt_pbkdf2_hmacsha256(salt, app.task_api_key)
		encrypted_password = crypt_aes(key, iv, request.form['bgpass'])
		out = app.hxtool_db.backgroundProcessorCredentialCreate(session['ht_profileid'], request.form['bguser'], HXAPI.b64(iv), HXAPI.b64(salt), encrypted_password)
		app.logger.info("Background Processing credentials set profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		hxtool_global.task_hx_api_sessions[session['ht_profileid']] = HXAPI(hx_api_object.hx_host, 
																			hx_port = hx_api_object.hx_port, 
																			proxies = app.hxtool_config['network'].get('proxies'), 
																			headers = app.hxtool_config['headers'], 
																			cookies = app.hxtool_config['cookies'], 
																			logger = app.logger, 
																			default_encoding = default_encoding)																
		(ret, response_code, response_data) = hxtool_global.task_hx_api_sessions[session['ht_profileid']].restLogin(request.form['bguser'], request.form['bgpass'], auto_renew_token = True)
		if ret:
			app.logger.info("Successfully initialized task API session for profile {}".format(session['ht_profileid']))
		else:
			app.logger.error("Failed to initialized task API session for profile {}".format(session['ht_profileid']))
	if request.args.get('unset'):
		out = app.hxtool_db.backgroundProcessorCredentialRemove(session['ht_profileid'])
		hx_api_object = hxtool_global.task_hx_api_sessions.get(session['ht_profileid'])
		if hx_api_object and hx_api_object.restIsSessionValid():
			(ret, response_code, response_data) = hx_api_object.restLogout()
			del hxtool_global.task_hx_api_sessions[session['ht_profileid']]
		app.logger.info("Background Processing credentials unset profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/settings", code=302)
	
	bgcreds = formatProfCredsInfo((app.hxtool_db.backgroundProcessorCredentialGet(session['ht_profileid']) is not None))
	
	return render_template('ht_settings.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bgcreds=bgcreds)


			
### Custom Configuration Channels
@app.route('/channels', methods=['GET', 'POST'])
@valid_session_required
def channels(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListCustomConfigChannels(limit=1)
	if ret:
	
		if (request.method == 'POST'):
			(ret, response_code, response_data) = hx_api_object.restNewConfigChannel(request.form['name'], request.form['description'], request.form['priority'], request.form.getlist('hostsets'), request.form['confjson'])
			app.logger.info("New configuration channel on profile: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		
		if request.args.get('delete'):
			(ret, response_code, response_data) = hx_api_object.restDeleteConfigChannel(request.args.get('delete'))
			app.logger.info("Configuration channel delete on profile: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return redirect("/channels", code=302)
		
		(ret, response_code, response_data) = hx_api_object.restListCustomConfigChannels()
		channels = formatCustomConfigChannels(response_data)
		
		(ret, response_code, response_data) = hx_api_object.restListHostsets()
		hostsets = formatHostsets(response_data)
		
		return render_template('ht_configchannel.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), channels=channels, hostsets=hostsets)
	else:
		return render_template('ht_noaccess.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
			

@app.route('/channelinfo', methods=['GET'])
@valid_session_required
def channelinfo(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListCustomConfigChannels(limit=1)
	if ret:
		# TODO: finish
		(ret, response_code, response_data) = hx_api_object.restGetConfigChannelConfiguration(request.args.get('id'))
		return render_template('ht_configchannel_info.html', channel_json = json.dumps(response_data, sort_keys = False, indent = 4))
	else:
		return render_template('ht_noaccess.html')
		
#### Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
	
	if (request.method == 'POST'):
		if 'ht_user' in request.form:
			ht_profile = app.hxtool_db.profileGet(request.form['controllerProfileDropdown'])
			if ht_profile:	

				hx_api_object = HXAPI(ht_profile['hx_host'], hx_port = ht_profile['hx_port'], proxies = app.hxtool_config['network'].get('proxies'), headers = app.hxtool_config['headers'], cookies = app.hxtool_config['cookies'], logger = app.logger, default_encoding = default_encoding)

				(ret, response_code, response_data) = hx_api_object.restLogin(request.form['ht_user'], request.form['ht_pass'], auto_renew_token = True)
				if ret:
					# Set session variables
					session['ht_user'] = request.form['ht_user']
					session['ht_profileid'] = ht_profile['profile_id']
					session['ht_api_object'] = hx_api_object.serialize()
					session['hx_version'] = hx_api_object.hx_version
					app.logger.info("Successful Authentication - User: %s@%s:%s", session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
					redirect_uri = request.args.get('redirect_uri')
					if not redirect_uri:
						redirect_uri = "/"
					return redirect(redirect_uri, code=302)
				else:
					return render_template('ht_login.html', fail=response_data)		
		return render_template('ht_login.html', hx_default_port = HXAPI.HX_DEFAULT_PORT, fail = "Invalid profile id.")
	else:	
		return render_template('ht_login.html', hx_default_port = HXAPI.HX_DEFAULT_PORT)
		
@app.route('/logout', methods=['GET'])
def logout():
	if session:
		if 'ht_api_object' in session:
			hx_api_object = HXAPI.deserialize(session['ht_api_object'])
			hx_api_object.restLogout()
			app.logger.info('User logged out: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			hx_api_object = None	
		session.clear()
	return redirect("/login", code=302)
	

####################################
#
#	HXTool API
#	
####################################

@app.route('/api/v{0}/vegalite_inactive_hosts_per_hostset'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_inactive_hosts_per_hostset(hx_api_object):
	if request.method == 'GET':
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
			return(app.response_class(response=json.dumps(results), status=200, mimetype='application/json'))
		else:
			return('',500)

@app.route('/api/v{0}/vegalite_events_timeline'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_events_timeline(hx_api_object):
	if request.method == 'GET':
		mydates = []
		mycount = {}

		# Get all dates and calculate delta
		startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
		endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
		delta = (endDate - startDate)

		# Generate data for all dates
		date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
		for date in date_list:
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

			# Append data to our list
			for key, stats in mycount.items():
				mydates.append({"date": key + "T00:00:00.000Z", "count": stats['IOC'], "type": "Indicator"})
				mydates.append({"date": key + "T00:00:00.000Z", "count": stats['EXD'], "type": "Exploit Guard"})
				mydates.append({"date": key + "T00:00:00.000Z", "count": stats['MAL'], "type": "Malware"})

		else:
			return('',500)

		return(app.response_class(response=json.dumps(mydates), status=200, mimetype='application/json'))


@app.route('/api/v{0}/vegalite_events_distribution'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_events_distribution(hx_api_object):
	if request.method == 'GET':

		mydata = []
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

			for key, data in mycount.items():
				mydata.append({"source": key, "count": data})

		else:
			return('',500)

		return(app.response_class(response=json.dumps(mydata), status=200, mimetype='application/json'))


@app.route('/api/v{0}/vegalite_hosts_initial_agent_checkin'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_hosts_initial_agent_checkin(hx_api_object):
	if request.method == 'GET':

		myhosts = []
		mycount = {}

		# Get all dates and calculate delta
		startDate = datetime.datetime.strptime(request.args.get('startDate'), '%Y-%m-%d')
		endDate = datetime.datetime.strptime(request.args.get('endDate'), '%Y-%m-%d')
		delta = (endDate - startDate)

		# Generate data for all dates
		date_list = [endDate - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
		for date in date_list:
			mycount[date.strftime("%Y-%m-%d")] = 0

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				if host['initial_agent_checkin'][0:10] in mycount.keys():
					mycount[host['initial_agent_checkin'][0:10]] += 1

			# Append data to our list
			for key, stats in mycount.items():
				myhosts.append({"initial_checkin": key, "count": stats})
		else:
			return('', 500)

		return(app.response_class(response=json.dumps(myhosts), status=200, mimetype='application/json'))


@app.route('/api/v{0}/datatable_hosts_with_alerts'.format(HXTOOL_API_VERSION), methods=['GET'])
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

		mydata = {"data": myhosts[:5]}

		return(app.response_class(response=json.dumps(mydata), status=200, mimetype='application/json'))


@app.route('/api/v{0}/datatable_alerts'.format(HXTOOL_API_VERSION), methods=['GET'])
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


@app.route('/api/v{0}/datatable_alerts_full'.format(HXTOOL_API_VERSION), methods=['GET'])
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

		if 'hostname' in request.args:
			(ret, response_code, response_data) = hx_api_object.restListHosts(search_term = request.args.get('hostname'))
			if ret:
				myhostlist = []
				for hostname in response_data['data']['entries']:
					myhostlist.append(hostname['_id'])
				myfilters['agent._id'] = myhostlist

		if len(myfilters) > 0:
			(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'), filters=myfilters)
		else:
			(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(request.args.get('startDate'), request.args.get('endDate'))
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

@app.route('/api/v{0}/vegalite_malwarecontent'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_malwarecontent(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(host['_id'])
				if 'malware' in sresponse_data['data'].keys():
					if 'content' in sresponse_data['data']['malware'].keys():
						if not sresponse_data['data']['malware']['content']['version'] in myContent.keys():
							myContent[sresponse_data['data']['malware']['content']['version']] = 1
						else:
							myContent[sresponse_data['data']['malware']['content']['version']] += 1
					else:
						myContent['none'] += 1
				else:
					myContent['none'] += 1

		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "version": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		return(app.response_class(response=json.dumps(results), status=200, mimetype='application/json'))

@app.route('/api/v{0}/vegalite_malwareengine'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_malwareengine(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0

		(ret, response_code, response_data) = hx_api_object.restListHosts(limit=100000)
		if ret:
			for host in response_data['data']['entries']:
				(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(host['_id'])
				if 'malware' in sresponse_data['data'].keys():
					if 'engine' in sresponse_data['data']['malware'].keys():
						if not sresponse_data['data']['malware']['engine']['version'] in myContent.keys():
							myContent[sresponse_data['data']['malware']['engine']['version']] = 1
						else:
							myContent[sresponse_data['data']['malware']['engine']['version']] += 1
					else:
						myContent['none'] += 1
				else:
					myContent['none'] += 1

		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "version": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		return(app.response_class(response=json.dumps(results), status=200, mimetype='application/json'))

@app.route('/api/v{0}/vegalite_malwarestatus'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def vegalite_malwarestatus(hx_api_object):
	if request.method == 'GET':
		
		myContent = {}
		myContent['none'] = 0

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

		mylist = []
		for ckey, cval in myContent.items():
			mylist.append({ "mode": ckey, "count": cval })

		newlist = sorted(mylist, key=lambda k: k['count'])
		results = newlist[-10:]

		return(app.response_class(response=json.dumps(results), status=200, mimetype='application/json'))

@app.route('/api/v{0}/datatable_scripts'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_scripts(hx_api_object):
	if request.method == 'GET':
		myscripts = app.hxtool_db.scriptList()
		return(app.response_class(response=json.dumps(myscripts), status=200, mimetype='application/json'))

@app.route('/api/v{0}/datatable_openioc'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_openioc(hx_api_object):
	if request.method == 'GET':
		myiocs = app.hxtool_db.oiocList()
		return(app.response_class(response=json.dumps(myiocs), status=200, mimetype='application/json'))

@app.route('/api/v{0}/datatable_taskprofiles'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_taskprofiles(hx_api_object):
	if request.method == 'GET':
		mytaskprofiles = app.hxtool_db.taskProfileList()
		return(app.response_class(response=json.dumps(mytaskprofiles), status=200, mimetype='application/json'))

@app.route('/api/v{0}/datatable_acqs'.format(HXTOOL_API_VERSION), methods=['GET'])
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

@app.route('/api/v{0}/getHealth'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def getHealth(hx_api_object):
	myHealth = {}
	(ret, response_code, response_data) = hx_api_object.restGetControllerVersion()
	if ret:
		myHealth['status'] = "OK"
		myHealth['version'] = response_data['data']
		print(myHealth)
		return(app.response_class(response=json.dumps(myHealth), status=200, mimetype='application/json'))
	else:
		myHealth['status'] = "FAIL"
		print(myHealth)
		return(app.response_class(response=json.dumps(myHealth), status=200, mimetype='application/json'))

@app.route('/api/v{0}/datatable_es'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def datatable_es(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListSearches()
	if ret:
		mysearches = {"data": []}
		for search in response_data['data']['entries']:
			mysearches['data'].append({
				"DT_RowId": search['_id'],
				"state": search['state'],
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


@app.route('/api/v{0}/datatable_es_result_types'.format(HXTOOL_API_VERSION), methods=['GET'])
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

@app.route('/api/v{0}/datatable_es_result'.format(HXTOOL_API_VERSION), methods=['GET'])
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


@app.route('/api/v{0}/scheduler_health'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def scheduler_health(hx_api_object):
	return(app.response_class(response=json.dumps(hxtool_global.hxtool_scheduler.status()), status=200, mimetype='application/json'))

@app.route('/api/v{0}/scheduler_tasks'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def scheduler_tasks(hx_api_object):
	mytasks = {}
	mytasks['data'] = []
	for task in hxtool_global.hxtool_scheduler.tasks():
		mytasks['data'].append({
			"DT_RowId": task['task_id'],
			"profile": task['profile_id'],
			"parent_id": task['parent_id'],
			"name": task['name'],
			"enabled": task['enabled'],
			"last_run": str(task['last_run']),
			"next_run": str(task['next_run']),
			"immutable": task['immutable'],
			"state": task_state_description.get(task['state'], "Unknown")
			})
	return(app.response_class(response=json.dumps(mytasks), status=200, mimetype='application/json'))



@app.route('/api/v{0}/datatable_bulk'.format(HXTOOL_API_VERSION), methods=['GET'])
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
					if ret:
						try:
							myhostsetname = hresponse_data['data']['entries'][0]['name']
						except(KeyError):
							myhostsetname = "N/A"
					else:
						myhostsetname = "N/A"
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
		
####################
# Utility Functions
####################
def submit_bulk_job(hx_api_object, hostset_id, script_xml, start_time = None, interval = None, comment = None, download = True, task_profile = None, skip_base64 = False):
	bulk_download_eid = None
	task_list = None
	
	bulk_acquisition_task = hxtool_scheduler_task(session['ht_profileid'], 'Bulk Acquisition ID: pending', start_time = start_time, interval = interval)
	
	# So it turns out theres a nasty race condition that was happening here:
	# the call to restListBulkHosts() was returning no hosts because the bulk
	# acquisition hadn't been queued up yet. So instead, we walk the host set
	# in order to retrieve the hosts targeted for the job.
	if download:
		bulk_download_eid = app.hxtool_db.bulkDownloadCreate(session['ht_profileid'], hostset_id = hostset_id, task_profile = task_profile)
		
		(ret, response_code, response_data) = hx_api_object.restListHostsInHostset(hostset_id)
		bulk_acquisition_hosts = {}
		task_list = []
		for host in response_data['data']['entries']:
			bulk_acquisition_hosts[host['_id']] = {'downloaded' : False, 'hostname' :  host ['hostname']}
			download_and_process_task = hxtool_scheduler_task(session['ht_profileid'], 'Bulk Acquisition Download: {}'.format(host['hostname']), parent_id = bulk_acquisition_task.task_id, start_time = start_time, interval = interval)
			download_and_process_task.add_step(bulk_download_task_module, kwargs = {
														'bulk_download_eid' : bulk_download_eid,
														'host_id' : host['_id'],
														'host_name' : host['hostname']
													})

			# TODO: This is awful, needs to be rewritten where the individual function(stacking, multifile, etc) adds the necessary step
			# TODO: and each module defines the necessary parameters required.
			# The bulk_acquisition_task_module passes the host_id and host_name values to these modules
			if task_profile:
				if task_profile == 'stacking':
					download_and_process_task.add_step(stacking_task_module, kwargs = {
																'delete_bulk_download' : True
															})
					comment = "HXTool Stacking Acquisition"										
				elif task_profile == 'file_listing':
					download_and_process_task.add_step(file_listing_task_module, kwargs = {
																'delete_bulk_download' : False
															})
					comment = "HXTool Multifile File Listing Acquisition"										
				elif task_profile:
					task_profile = app.hxtool_db.taskProfileGet(task_profile)
					if task_profile:
						#TODO: once task profile page params are dynamic, remove static mappings
						for task_module_params in task_profile['params']:						
							if task_module_params['module'] == 'ip':
								download_and_process_task.add_step(streaming_task_module, kwargs = {
																	'stream_host' : task_module_params['targetip'],
																	'stream_port' : task_module_params['targetport'],
																	'stream_protocol' : task_module_params['protocol'],
																	'batch_mode' : (task_module_params['eventmode'] != 'per-event'),
																	'delete_bulk_download' : False
																})
							elif task_module_params['module'] == 'file':
								download_and_process_task.add_step(file_write_task_module, kwargs = {
																	'file_name' : task_module_params['filepath'],
																	'batch_mode' : (task_module_params['eventmode'] != 'per-event'),
																	'delete_bulk_download' : False
																})
			task_list.append(download_and_process_task)
		
		app.hxtool_db.bulkDownloadUpdate(bulk_download_eid, hosts = bulk_acquisition_hosts)
		
	bulk_acquisition_task.add_step(bulk_acquisition_task_module, kwargs = {
									'script' : script_xml,
									'hostset_id' : hostset_id,
									'comment' : comment,
									'skip_base64' : skip_base64,
									'download' : download,
									'bulk_download_eid' : bulk_download_eid
								})
	
	hxtool_global.hxtool_scheduler.add(bulk_acquisition_task)	
	
	if task_list:
		hxtool_global.hxtool_scheduler.add_list(task_list)	
	
	return bulk_download_eid
		
		
###########
### Main ####
###########			
def logout_task_sessions():
	for profile_id in hxtool_global.task_hx_api_sessions:
		hx_api_object = hxtool_global.task_hx_api_sessions[profile_id]
		if hx_api_object:
			hx_api_object.restLogout()
			hx_api_object = None


def sigint_handler(signum, frame):
	app.logger.info("Caught SIGINT, exiting...")
	logout_task_sessions()
	if hxtool_global.hxtool_scheduler:
		hxtool_global.hxtool_scheduler.stop()
	if hxtool_global.hxtool_db:
		hxtool_global.hxtool_db.close()
	if app.hxtool_db:
		app.hxtool_db.close()	
	exit(0)	


def app_init(debug = False):
	hxtool_global.app_instance_path = app.root_path
	
	
	# Log early init/failures to stdout
	console_log = logging.StreamHandler(sys.stdout)
	console_log.setFormatter(logging.Formatter('[%(asctime)s] {%(module)s} {%(threadName)s} %(levelname)s - %(message)s'))
	app.logger.addHandler(console_log)
	
	# Init DB
	app.hxtool_db = hxtool_db('hxtool.db', logger = app.logger)
	hxtool_global.hxtool_db = app.hxtool_db
	
	# If we're debugging use a static key
	if debug:
		app.secret_key = 'B%PT>65`)x<3_CRC3S~D6CynM7^F~:j0'.encode(default_encoding)
		app.logger.setLevel(logging.DEBUG)
		app.logger.debug("Running in debugging mode.")
	else:
		app.secret_key = crypt_generate_random(32)
		app.logger.setLevel(logging.INFO)
	
	app.hxtool_config = hxtool_config(combine_app_path('conf.json'), logger = app.logger)
	hxtool_global.hxtool_config = app.hxtool_config
	
	app.task_api_key = 'Z\\U+z$B*?AiV^Fr~agyEXL@R[vSTJ%N&'.encode(default_encoding)
	
	# Initialize hxtool_global storage for task scheduler sessions
	hxtool_global.task_hx_api_sessions = {}
	
	# Loop through background credentials and start the API sessions
	profiles = hxtool_global.hxtool_db.profileList()
	for profile in profiles:
		task_api_credential = hxtool_global.hxtool_db.backgroundProcessorCredentialGet(profile['profile_id'])
		if task_api_credential:
			try:
				salt = HXAPI.b64(task_api_credential['salt'], True)
				iv = HXAPI.b64(task_api_credential['iv'], True)
				key = crypt_pbkdf2_hmacsha256(salt, app.task_api_key)
				decrypted_background_password = crypt_aes(key, iv, task_api_credential['hx_api_encrypted_password'], decrypt = True)
				hxtool_global.task_hx_api_sessions[profile['profile_id']] = HXAPI(profile['hx_host'], 
																					hx_port = profile['hx_port'], 
																					proxies = app.hxtool_config['network'].get('proxies'), 
																					headers = app.hxtool_config['headers'], 
																					cookies = app.hxtool_config['cookies'], 
																					logger = app.logger, 
																					default_encoding = default_encoding)																
				(ret, response_code, response_data) = hxtool_global.task_hx_api_sessions[profile['profile_id']].restLogin(task_api_credential['hx_api_username'], decrypted_background_password, auto_renew_token = True)
				if ret:
					app.logger.info("Successfully initialized task API session for profile {} ({})".format(profile['hx_host'], profile['profile_id']))
				else:
					app.logger.error("Failed to initialized task API session for profile {} ({})".format(profile['hx_host'], profile['profile_id']))
					del hxtool_global.task_hx_api_sessions[profile['profile_id']]
			except UnicodeDecodeError:
				app.logger.error("Please reset the background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
		else:
			app.logger.info("No background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
	
	# Initialize the scheduler
	hxtool_global.hxtool_scheduler = hxtool_scheduler(task_thread_count = app.hxtool_config['background_processor']['poll_threads'], logger = app.logger)
	hxtool_global.hxtool_scheduler.start()
	hxtool_global.hxtool_scheduler.load_from_database()
	
	
	# Initialize configured log handlers
	for log_handler in app.hxtool_config.log_handlers():
		app.logger.addHandler(log_handler)
	
	app.config['SESSION_COOKIE_NAME'] = "hxtool_session"
	app.permanent_session_lifetime = datetime.timedelta(days=7)
	app.session_interface = hxtool_session_interface(app, logger = app.logger, expiration_delta=app.hxtool_config['network']['session_timeout'])

debug_mode = False
if __name__ == "__main__":
	signal.signal(signal.SIGINT, sigint_handler)
	
	if len(sys.argv) == 2 and sys.argv[1] == '-debug':
		debug_mode = True
	
	app_init(debug_mode)
	
	# WSGI request log - when not running under gunicorn or mod_wsgi
	logger = logging.getLogger('werkzeug')
	if logger:
		logger.setLevel(app.logger.level)
		request_log_handler = logging.handlers.RotatingFileHandler('log/access.log', maxBytes=50000, backupCount=5)
		request_log_formatter = logging.Formatter("[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s")
		request_log_handler.setFormatter(request_log_formatter)	
		logger.addHandler(request_log_handler)

	# Start
	app.logger.info('Application starting')
	

	
	# TODO: This should really be after app.run, but you cannot run code after app.run, so we'll leave this here for now.
	app.logger.info("Application is running. Please point your browser to http{0}://{1}:{2}. Press Ctrl+C/Ctrl+Break to exit.".format(
																							's' if app.hxtool_config['network']['ssl'] == 'enabled' else '',
																							app.hxtool_config['network']['listen_address'], 
																							app.hxtool_config['network']['port']))
	if app.hxtool_config['network']['ssl'] == "enabled":
		app.config['SESSION_COOKIE_SECURE'] = True
		context = (app.hxtool_config['ssl']['cert'], app.hxtool_config['ssl']['key'])
		app.run(host=app.hxtool_config['network']['listen_address'], 
				port=app.hxtool_config['network']['port'], 
				ssl_context=context, 
				threaded=True)
	else:
		app.run(host=app.hxtool_config['network']['listen_address'], 
				port=app.hxtool_config['network']['port'])
	
else:
	# Running under gunicorn/mod_wsgi
	app_init(False)