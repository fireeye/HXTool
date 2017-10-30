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
import threading
import time
from functools import wraps
import xml.etree.ElementTree as ET
from string import Template
from xml.sax.saxutils import escape as xmlescape
import re

try:
	import StringIO
except ImportError:
	# Running on Python 3.x
	from io import StringIO
	from io import BytesIO

# Flask imports
try:
	from flask import Flask, request, Response, session, redirect, render_template, send_file, g, url_for, abort
	from jinja2 import evalcontextfilter, Markup, escape
except ImportError:
	print("hxtool requires the 'Flask' module, please install it.")
	exit(1)
	
# pycryptodome imports
try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
	from Crypto.Hash import HMAC, SHA256
except ImportError:
	print("hxtool requires the 'pycryptodome' module, please install it.")
	exit(1)
	
# hx_tool imports
from hx_lib import *
from hxtool_formatting import *
from hxtool_db import *
from hxtool_process import *
from hxtool_config import *
from hxtool_data_models import *


app = Flask(__name__, static_url_path='/static')

HXTOOL_API_VERSION = 1

ht_config = None
ht_db = None

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

# Dashboard page
################

@app.route('/')
@valid_session_required
def index(hx_api_object):
	if not 'render' in request.args:
		return render_template('ht_index_ph.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
	else:
	
		mytime = "week"
		time_matrix = {
			"today"	:	datetime.datetime.now(),
			"week"	:	datetime.datetime.now() - datetime.timedelta(days=7),
			"2weeks":	datetime.datetime.now() - datetime.timedelta(days=14),
			"30days":	datetime.datetime.now() - datetime.timedelta(days=30),
			"60days":	datetime.datetime.now() - datetime.timedelta(days=60),
			"90days":	datetime.datetime.now() - datetime.timedelta(days=90),
			"182days":	datetime.datetime.now() - datetime.timedelta(days=182),
			"365days":	datetime.datetime.now() - datetime.timedelta(days=365)
		}
		
		if 'time' in request.args and request.args.get('time') in time_matrix:
			mytime = request.args.get('time')
		
		starttime = time_matrix.get(mytime)
		
		interval_select = ""
		for i in ["today", "week", "2weeks", "30days", "60days", "90days", "182days", "365days"]:
				interval_select += '<option value="/?time={0}"{1}>{2}</option>'.format(i, ' selected="selected"' if i == mytime else '', i)
			
		base = datetime.datetime.today()
	
		(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(starttime.strftime("%Y-%m-%d"), base.strftime("%Y-%m-%d"))
		
		nr_of_alerts = len(response_data)
		
		# Recent alerts
		alerts = formatDashAlerts(response_data, hx_api_object)
		
		stats = [{'value': 0, 'label': 'Exploit'}, {'value': 0, 'label': 'IOC'}, {'value': 0, 'label': 'Malware'}]
		if nr_of_alerts > 0:
			stats[0]['value'] = len([_ for _ in response_data if _['source'] == "EXD"])
			stats[1]['value'] = len([_ for _ in response_data if _['source'] == "IOC"])
			stats[2]['value'] = len([_ for _ in response_data if _['source'] == "MAL"])
			
			stats[0]['value'] = round((stats[0]['value'] / float(nr_of_alerts)) * 100)
			stats[1]['value'] = round((stats[1]['value'] / float(nr_of_alerts)) * 100)
			stats[2]['value'] = round((stats[2]['value'] / float(nr_of_alerts)) * 100)

		# Event timeline last 30 days
		talert_dates = {}
	
		
		delta = (base - starttime)
		
		date_list = [base - datetime.timedelta(days=x) for x in range(0, delta.days + 1)]
		for date in date_list:
			talert_dates[date.strftime("%Y-%m-%d")] = 0

		ioclist = []
		exdlist = []
		mallist = []
		
		for talert in response_data:
			if talert['source'] == "IOC":
				if not talert['agent']['_id'] in ioclist:
					ioclist.append(talert['agent']['_id'])
				
			if talert['source'] == "EXD":
				if not talert['agent']['_id'] in exdlist:
					exdlist.append(talert['agent']['_id'])
			
			if talert['source'] == "MAL":
				if not talert['agent']['_id'] in mallist:
					mallist.append(talert['agent']['_id'])			
			
			date = talert['event_at'][0:10]
			if date in talert_dates.keys():
				talert_dates[date] = talert_dates[date] + 1

		ioccounter = len(ioclist)
		exdcounter = len(exdlist)
		malcounter = len(mallist)
		
		talerts_list = []
		for key in talert_dates:
			talerts_list.append({"date": str(key), "count": talert_dates[key]})

		# Info table
		(ret, response_code, response_data) = hx_api_object.restListHosts()
		hostcounter = len(response_data['data']['entries']);
		contcounter = len([_ for _ in response_data['data']['entries'] if _['containment_state'] != "normal"]);

		(ret, response_code, response_data) = hx_api_object.restListSearches()
		searchcounter = len([_ for _ in response_data['data']['entries'] if _['state'] == "RUNNING"])

		(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
		blkcounter = len([_ for _ in response_data['data']['entries'] if _['state'] == "RUNNING"]);

		return render_template('ht_index.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), alerts=alerts, iocstats=json.dumps(stats), timeline=json.dumps(talerts_list), contcounter=str(contcounter), hostcounter=str(hostcounter), malcounter=str(malcounter), searchcounter=str(searchcounter), blkcounter=str(blkcounter), exdcounter=str(exdcounter), ioccounter=str(ioccounter), iselect=interval_select)
			
### Jobdash
##########

@app.route('/jobdash', methods=['GET', 'POST'])
@valid_session_required
def jobdash(hx_api_object):
	blk = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], session['ht_port'])
	jobsBulk = formatBulkTableJobDash(c, conn, blk, session['ht_profileid'])

	s = restListSearches(session['ht_token'], session['ht_ip'], session['ht_port'])
	jobsEs = formatListSearchesJobDash(s)
	
	
	return render_template('ht_jobdash.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), jobsBulk=jobsBulk, jobsEs=jobsEs)

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
		(ret, response_code, response_data) = hx_api_object.restFindHostsBySearchString(request.args.get('q'))
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
		
### Alerts Page
###################

@app.route('/alerts', methods=['GET', 'POST'])
@valid_session_required
def alerts(hx_api_object):
		
	if request.method == "POST" and 'annotateText' in request.form:
		# We have a new annotation
		ht_db.alertCreate(session['ht_profileid'], request.form['annotateId'])
		ht_db.alertAddAnnotation(session['ht_profileid'], request.form['annotateId'], request.form['annotateText'], request.form['annotateState'], session['ht_user'])
		app.logger.info('New annotation - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/alerts?acount=30", code=302)
	
	if not 'render' in request.args:
		return render_template('ht_alerts_ph.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
	else:
		if 'acount' in request.args and request.args['acount']:
			acount = int(request.args['acount'])
		else:
			acount = 50
	
		acountselect = ""
		for i in [10, 20, 30, 50, 100, 250, 500, 1000]:
			acountselect += '<option value="/alerts?acount={0}"{1}>Last {2} Alerts</option>'.format(i, ' selected="selected"' if i == acount else '', i)
				
		(ret, response_code, response_data) = hx_api_object.restGetAlerts(acount)
		alertshtml = formatAlertsTable(response_data, hx_api_object, session['ht_profileid'], ht_db)
		return render_template('ht_alerts.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), alerts=alertshtml, acountselect=acountselect)
		
@app.route('/annotatedisplay', methods=['GET'])
@valid_session_required
def annotatedisplay(hx_api_object):	
	if 'alertid' in request.args:
		alert = ht_db.alertGet(session['ht_profileid'], request.args.get('alertid'))
		an = None
		if alert:
			an = alert['annotations']
		annotatetable = formatAnnotationTable(an)

	return render_template('ht_annotatedisplay.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), annotatetable=annotatetable)


#### Enterprise Search
#########################

@app.route('/search', methods=['GET', 'POST'])
@valid_session_required
def search(hx_api_object):	
	# If we get a post it's a new sweep
	if request.method == 'POST':
		f = request.files['newioc']
		rawioc = f.read()
		(ret, response_code, response_data) = hx_api_object.restSubmitSweep(rawioc, request.form['sweephostset'])
		app.logger.info('New Enterprise Search - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)

	(ret, response_code, response_data) = hx_api_object.restListSearches()
	searches = formatListSearches(response_data)
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	return render_template('ht_searchsweep.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), searches=searches, hostsets=hostsets)

@app.route('/searchresult', methods=['GET'])
@valid_session_required
def searchresult(hx_api_object):
	if request.args.get('id'):
		(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'))
		res = formatSearchResults(response_data)
		return render_template('ht_search_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), result=res)
			
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
		
#### Build a real-time indicator
####################################

@app.route('/buildioc', methods=['GET', 'POST'])
@valid_session_required
def buildioc(hx_api_object):
	# New IOC to be created
	if request.method == 'POST':
	
		if request.form['platform'] == "all":
			myplatforms = ['win', 'osx']
		else:
			myplatforms = request.form['platform'].split(",")
			
		(ret, response_code, response_data) = hx_api_object.restAddIndicator(session['ht_user'], request.form['iocname'], myplatforms, request.form['cats'])
		app.logger.info('New indicator created - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		
		ioc_guid = response_data['data']['_id']

		condEx = []
		condPre = []

		for fieldname, value in request.form.items():
			if "cond_" in fieldname:
				condComp = fieldname.split("_")
				if (condComp[2] == "presence"):
					condPre.append(value.rstrip(","))
				elif (condComp[2] == "execution"):
					condEx.append(value.rstrip(","))

		for data in condPre:
			data = """{"tests":[""" + data + """]}"""
			data = data.replace('\\', '\\\\')
			(ret, response_code, response_data) = hx_api_object.restAddCondition(request.form['cats'], ioc_guid, 'presence', data)
			
		for data in condEx:
			data = """{"tests":[""" + data + """]}"""
			data = data.replace('\\', '\\\\')
			(ret, response_code, response_data) = hx_api_object.restAddCondition(request.form['cats'], ioc_guid, 'execution', data)
			
	(ret, response_code, response_data) = hx_api_object.restListIndicatorCategories()
	cats = formatCategoriesSelect(response_data)
	return render_template('ht_buildioc.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), cats=cats)

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
			ioclist[ioc['uuid']]['platforms'] = ioc['platforms']

			#Grab execution indicators
			(ret, response_code, response_data) = hx_api_object.restGetCondition(ioc['category'], ioc['uuid'], 'execution')
			for item in response_data['data']['entries']:
				ioclist[ioc['uuid']]['execution'].append(item['tests'])

			#Grab presence indicators
			(ret, response_code, response_data) = hx_api_object.restGetCondition(ioc['category'], ioc['uuid'], 'presence')
			for item in response_data['data']['entries']:
				ioclist[ioc['uuid']]['presence'].append(item['tests'])
					
		ioclist_json = json.dumps(ioclist, indent=4)
		
		if len(iocs) == 1:
			iocfname = iocs[0]['name'] + ".ioc"
		else:
			iocfname = "multiple_indicators.ioc"
		
		try:
			buffer = BytesIO()
		except NameError:
			# Python 2.x, try StringIO
			buffer = StringIO()
		buffer.write(ioclist_json.encode('utf-8'))
		buffer.seek(0)
		app.logger.info('Indicator(s) exported - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return send_file(buffer, attachment_filename=iocfname, as_attachment=True)

	(ret, response_code, response_data) = hx_api_object.restListIndicators()
	indicators = formatIOCResults(response_data)
	return render_template('ht_indicators.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), indicators=indicators)

@app.route('/indicatorcondition')
@valid_session_required
def indicatorcondition(hx_api_object):
	uuid = request.args.get('uuid')
	category = request.args.get('category')

	(ret, response_code, condition_class_presence) = hx_api_object.restGetCondition(category, uuid, 'presence')
	(ret, response_code, condition_class_execution) = hx_api_object.restGetCondition(category, uuid, 'execution')
	
	conditions = formatConditions(condition_class_presence, condition_class_execution)

	return render_template('ht_indicatorcondition.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), conditions=conditions)

		

@app.route('/categories', methods=['GET', 'POST'])
@valid_session_required
def categories(hx_api_object):
	if request.method == 'POST':
		catname = request.form.get('catname')
		(ret, response_code, response_data) = hx_api_object.restCreateCategory(str(catname))
		app.logger.info('New indicator category created - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)


	(ret, response_code, response_data) = hx_api_object.restListIndicatorCategories()
	categories = formatCategories(response_data)
	
	return render_template('ht_categories.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), categories=categories)

@app.route('/import', methods=['POST'])
@valid_session_required
def importioc(hx_api_object):
	if request.method == 'POST':
	
		fc = request.files['iocfile']				
		iocs = json.loads(fc.read())
		
		for iockey in iocs:
			myplatforms = iocs[iockey]['platforms']
			if ',' in myplatforms:
				myplatforms = myplatforms.split(",")
	
			(ret, response_code, response_data) = hx_api_object.restAddIndicator(session['ht_user'], iocs[iockey]['name'], myplatforms, iocs[iockey]['category'])

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
	
	return redirect("/indicators", code=302)



### Bulk Acqusiitions
#########################

@app.route('/bulk', methods=['GET', 'POST'])
@valid_session_required
def listbulk(hx_api_object):
	if request.method == 'POST':
		f = request.files['bulkscript']
		bulk_acquisition_script = f.read()
		(ret, response_code, response_data) = hx_api_object.restListHostsInHostset(request.form['bulkhostset'])
		hosts = [{'_id' : host['_id']} for host in response_data['data']['entries']]
		(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(bulk_acquisition_script, hosts = hosts, comment = json.dumps({'hostset_id' : str(request.form['bulkhostset'])}))
		app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)

	(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
	bulktable = formatBulkTable(ht_db, response_data, session['ht_profileid'])
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	return render_template('ht_bulk.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable, hostsets=hostsets)
	
@app.route('/bulkdetails', methods = ['GET'])
@valid_session_required
def bulkdetails(hx_api_object):
	if request.args.get('id'):

		(ret, response_code, response_data) = hx_api_object.restListBulkHosts(request.args.get('id'))
		bulktable = formatBulkHostsTable(response_data)

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
		multi_file = ht_db.multiFileGetById(request.args.get('mf_id'))
		if multi_file:
			file_records = list(filter(lambda f: int(f['acquisition_id']) == int(request.args.get('acq_id')), multi_file['files']))
			if file_records and file_records[0]:
				path = get_download_full_path(hx_api_object.hx_host, request.args.get('mf_id'), 'multi_file', file_records[0]['hostname'], request.args.get('acq_id'))
				app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('acq_id'))
				return send_file(path, attachment_filename=path.rsplit('/',1)[-1], as_attachment=True)
		else:
			return "HX controller responded with code {0}: {1}".format(response_code, response_data)
	abort(404)		

@app.route('/bulkaction', methods=['GET'])
@valid_session_required
def bulkaction(hx_api_object):

	if request.args.get('action') == "stop":
		(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', request.args.get('id'))
		app.logger.info('Bulk acquisition action STOP - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
		
	if request.args.get('action') == "remove":
		(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', request.args.get('id'))
		app.logger.info('Bulk acquisition action REMOVE - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)	
		
	if request.args.get('action') == "download":
		(ret, response_code, response_data) = hx_api_object.restListBulkHosts(request.args.get('id'))
		hosts = { host['host']['_id'] : {'downloaded' : False, 'hostname' :  host['host']['hostname']} for host in response_data['data']['entries'] }
		
		hostset_id = -1
		(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(request.args.get('id'))
		if ret and response_data['data']['comment'] and 'hostset_id' in response_data['data']['comment']:
			hostset_id = int(json.loads(response_data['data']['comment'])['hostset_id'])
			
		ret = ht_db.bulkDownloadCreate(session['ht_profileid'], request.args.get('id'), hosts, hostset_id = hostset_id)
		app.logger.info('Bulk acquisition action DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
		
	if request.args.get('action') == "stopdownload":
		ret = ht_db.bulkDownloadStop(session['ht_profileid'], request.args.get('id'))
		# Delete should really be done by the background processor
		ret = ht_db.bulkDownloadDelete(session['ht_profileid'], request.args.get('id'))
		app.logger.info('Bulk acquisition action STOP DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
				
### Reports
############

@app.route('/reports')
@valid_session_required
def reports(hx_api_object):
	return render_template('ht_reports.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

@app.route('/reportgen')
@valid_session_required
def reportgen(hx_api_object):
	if request.args.get('id'):
		if request.args.get('id') == "1":
			reportFrom = request.args.get('startDate')
			reportTo = request.args.get('stopDate')
			(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(reportFrom, reportTo)
			
			if request.args.get('type') == "csv":
				reportdata = str(formatAlertsCsv(response_data, hx_api_object))
				fname = 'report.csv'
				
		if request.args.get('id') == "2":
			reportFrom = request.args.get('startDate')
			reportTo = request.args.get('stopDate')		
			# add code here for report type 2
		
		return send_file(io.BytesIO(reportdata), attachment_filename=fname, as_attachment=True)

def submit_bulk_job(hx_api_object, hostset, script_xml, handler=None):
	(ret, response_code, response_data) = hx_api_object.restListHostsInHostset(hostset)
	hosts = []
	bulk_download_entry_hosts = {}
	for host in response_data['data']['entries']:
		hosts.append({'_id' : host['_id']})
		bulk_download_entry_hosts[host['_id']] = {'downloaded' : False, 'hostname' : host['hostname']}
	(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(script_xml, hosts = hosts)
	if ret:
		bulkid = response_data['data']['_id']
		# Store Job Record
		#TODO: Implement bulkDownloadCreate
		bulk_job_entry = ht_db.bulkDownloadCreate(session['ht_profileid'], bulkid, bulk_download_entry_hosts, hostset, post_download_handler = handler)
		return bulkid
	return None

@app.route('/multifile', methods=['GET', 'POST'])
@valid_session_required
def multifile(hx_api_object):
	profile_id = session['ht_profileid']
	if request.args.get('stop'):
		mf_job = ht_db.multiFileGetById(request.args.get('stop'))
		if mf_job:
			success = True
			#TODO: Stop each file acquisition or handle solely in remove?
			if success:
				ht_db.multiFileStop(mf_job.eid)
				app.logger.info('MultiFile Job ID {0} action STOP - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, mf_job.eid))

	elif request.args.get('remove'):
		mf_job = ht_db.multiFileGetById(request.args.get('remove'))
		if mf_job:
			success = True
			for f in mf_job['files']:
				uri = 'acqs/files/{0}'.format(f['acquisition_id'])
				(ret, response_code, response_data) = hx_api_object.restDeleteFile(uri)
				#TODO: Replace with delete of file from record
				if not f['downloaded']:
					self._ht_db.multiFileUpdateFile(self.profile_id, f.eid, f['acquisition_id'])
				if not ret:
					app.logger.error("Failed to remove file acquisition {0}".format(f['acquisition_id']))
					success = False
			if success:
				ht_db.multiFileDelete(mf_job.eid)
				app.logger.info('MultiFile Job ID {0} action REMOVE - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, mf_job.eid))

	#TODO: Make Configurable both from GUI and config file?
	elif request.method == 'POST':
		MAX_FILE_ACQUISITIONS = 50
		
		display_name = ('display_name' in request.form) and request.form['display_name'] or "{0} job at {1}".format(session['ht_user'], datetime.datetime.now())
		use_api_mode = ('use_api_mode' in request.form)

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
				file_listing = ht_db._db.table('file_listing').get(eid=int(fl_id))
				if not file_listing:
					app.logger.warn('File Listing %s does not exist - User: %s@%s:%s', session['ht_user'], fl_id, hx_api_object.hx_host, hx_api_object.hx_port)
					continue
				choice_files = [file_listing['files'][i] for i in file_ids if i <= len(file_listing['files'])]
				multi_file_id = ht_db.multiFileCreate(session['ht_user'], profile_id, display_name=display_name, file_listing_id=file_listing.eid, api_mode=use_api_mode)
				# Create a data acquisition for each file from its host
				for cf in choice_files:
					if cf['hostname'] in agent_ids:
						agent_id = agent_ids[cf['hostname']]
					else:
						(ret, response_code, response_data) = hx_api_object.restFindHostsBySearchString(cf['hostname'])
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
						ht_db.multiFileAddJob(multi_file_id, job_record)
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
		fl_job = ht_db.fileListingGetById(request.args.get('stop'))
		if fl_job:
			(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', fl_job['bulk_download_id'])
			if ret:
				ht_db.fileListingStop(fl_job.eid)
				ht_db.bulkDownloadStop(session['ht_profileid'], fl_job['bulk_download_id'])
				app.logger.info('File Listing ID {0} action STOP - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, fl_job.eid))
		return redirect("/multifile", code=302)

	elif request.args.get('remove'):
		fl_job = ht_db.fileListingGetById(request.args.get('remove'))
		if fl_job:
			(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', fl_job['bulk_download_id'])
			if ret:
				ht_db.fileListingDelete(fl_job.eid)
				ht_db.bulkDownloadDelete(session['ht_profileid'], fl_job['bulk_download_id'])
				app.logger.info('File Listing ID {0} action REMOVE - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, fl_job.eid))
		return redirect("/multifile", code=302)

	elif request.method == 'POST':
		# Get Acquisition Options from Form
		display_name = xmlescape(request.form['listing_name'])
		regex = xmlescape(request.form['listing_regex'])
		path = xmlescape(request.form['listing_path'])
		hostset = xmlescape(request.form['hostset'])
		depth = '-1'
		# Build a script from the template
		script_xml = None
		try:
			if regex:
				re.compile(regex)
			else:
				app.logger.warn("Regex is empty!!")
				regex = ''
			with open('templates/file_listing_script_template.xml') as f:
				t = Template(f.read())
				script_xml = t.substitute(regex=regex, path=path, depth=depth)
			if not display_name:
				display_name = 'hostset: {0} path: {1} regex: {2}'.format(hostset, path, regex)
		except re.error:
			#TODO: Handle invalid regex with response. (Inline AJAX?)
			raise
		if script_xml:
			bulkid = submit_bulk_job(hx_api_object, hostset, script_xml.encode('utf-8'), handler="file_listing")
			ret = ht_db.fileListingCreate(session['ht_profileid'], session['ht_user'], bulkid, path, regex, depth, display_name)
			app.logger.info('New File Listing - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return redirect("/multifile", code=302)
		else:
			# TODO: Handle this condition 
			abort(404)

	#TODO: Modify template and move to Ajax
	fl_id = request.args.get('id')
	file_listing = ht_db.fileListingGetById(fl_id)
	fl_results = file_listing['files']
	display_fields = ['FullPath', 'Username', 'SizeInBytes', 'Modified', 'Sha256sum'] 

	return render_template('ht_file_listing.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), file_listing=file_listing, fl_results=fl_results, display_fields=display_fields)

@app.route('/_multi_files')
@valid_session_required
def get_multi_files(hx_api_object):
	profile_id = session['ht_profileid']
	data_rows = []
	for mf in ht_db.multiFileList(profile_id):
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
	for j in ht_db.fileListingList(profile_id):
		job = dict(j)
		job.update({'id': j.eid})
		job['state'] = ("STOPPED" if job['stopped'] else "RUNNING")
		job['file_count'] = len(job.pop('files'))

		# Completion rate
		bulk_download = ht_db.bulkDownloadGet(profile_id, job['bulk_download_id'])
		if bulk_download:
			hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
			job_progress = int(hosts_completed / float(len(bulk_download['hosts'])) * 100)
			job['display_name'] = 'hostset {0}, path: {1} regex: {2}'.format(bulk_download['hostset_id'] , job['cfg']['path'], job['cfg']['regex'])
		else:
			job_progress = job['file_count'] > 1 and 100 or 0
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
##########
@app.route('/stacking', methods=['GET', 'POST'])
@valid_session_required
def stacking(hx_api_object):
	if request.args.get('stop'):
		stack_job = ht_db.stackJobGetById(request.args.get('stop'))
		if stack_job:
			(ret, response_code, response_data) = hx_api_object.restCancelJob('acqs/bulk', stack_job['bulk_download_id'])
			if ret:
				ht_db.stackJobStop(stack_job.eid)
				ht_db.bulkDownloadStop(session['ht_profileid'], stack_job['bulk_download_id'])
				app.logger.info('Data stacking action STOP - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)

	if request.args.get('remove'):
		stack_job = ht_db.stackJobGetById(request.args.get('remove'))
		if stack_job:
			(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', stack_job['bulk_download_id'])
			if ret:
				ht_db.stackJobDelete(stack_job.eid)
				ht_db.bulkDownloadDelete(session['ht_profileid'], stack_job['bulk_download_id'])
				app.logger.info('Data stacking action REMOVE - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)

		
	if request.method == 'POST':
		stack_type = hxtool_data_models.stack_types.get(request.form['stack_type'])
		if stack_type:
			with open(os.path.join('scripts', stack_type['script']), 'rb') as f:
				script_xml = f.read()
				hostset_id = request.form['stackhostset']
				app.logger.info('Data stacking: New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				bulk_id = submit_bulk_job(hx_api_object, hostset_id, script_xml, handler="stacking")
				ret = ht_db.stackJobCreate(session['ht_profileid'], bulk_id, request.form['stack_type'])
				app.logger.info('New data stacking job - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
		return redirect("/stacking", code=302)
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	stacktable = formatStackTable(ht_db, session['ht_profileid'], response_data)
	
	return render_template('ht_stacking.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable, hostsets=hostsets, stack_types = hxtool_data_models.stack_types)


@app.route('/stackinganalyze', methods=['GET', 'POST'])
@valid_session_required
def stackinganalyze(hx_api_object):
	return render_template('ht_stacking_analyze.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stack_id = request.args.get('id'))
		
			
### Settings
############
			
@app.route('/settings', methods=['GET', 'POST'])
@valid_session_required
def settings(hx_api_object):
	if request.method == 'POST':
		key = HXAPI.b64(session['key'], True)
		# Generate a new IV - must be 16 bytes
		iv = crypt_generate_random(16)
		encrypted_password = crypt_aes(key, iv, request.form['bgpass'])
		salt = HXAPI.b64(session['salt'], True)
		out = ht_db.backgroundProcessorCredentialCreate(session['ht_profileid'], request.form['bguser'], HXAPI.b64(iv), HXAPI.b64(salt), encrypted_password)
		app.logger.info("Background Processing credentials set profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		start_background_processor(session['ht_profileid'], request.form['bguser'], request.form['bgpass'])
	if request.args.get('unset'):
		out = ht_db.backgroundProcessorCredentialRemove(session['ht_profileid'])
		app.logger.info("Background Processing credentials unset profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/settings", code=302)
	
	bgcreds = formatProfCredsInfo((ht_db.backgroundProcessorCredentialGet(session['ht_profileid']) is not None))
	
	return render_template('ht_settings.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bgcreds=bgcreds)


			
### Custom Configuration Channels
########################
@app.route('/channels', methods=['GET', 'POST'])
@valid_session_required
def channels(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restCheckAccessCustomConfig()
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
		
		return render_template('ht_configchannel.html', channels=channels, hostsets=hostsets)
	else:
		return render_template('ht_noaccess.html')
			

@app.route('/channelinfo', methods=['GET'])
@valid_session_required
def channelinfo(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restCheckAccessCustomConfig()
	if ret:
		# TODO: finish
		(ret, response_code, response_data) = hx_api_object.restGetConfigChannelConfiguration(request.args.get('id'))
		return render_template('ht_configchannel_info.html', channel_json = json.dumps(response_data, sort_keys = True, indent = 4))
	else:
		return render_template('ht_noaccess.html')
		
#### Authentication
#######################

@app.route('/login', methods=['GET', 'POST'])
def login():
	
	if (request.method == 'POST'):
		if 'ht_user' in request.form:
			ht_profile = ht_db.profileGet(request.form['controllerProfileDropdown'])
			if ht_profile:	

				hx_api_object = HXAPI(ht_profile['hx_host'], hx_port = ht_profile['hx_port'], proxies = ht_config['network'].get('proxies'), headers = ht_config['headers'], cookies = ht_config['cookies'], logger = app.logger)

				(ret, response_code, response_data) = hx_api_object.restLogin(request.form['ht_user'], request.form['ht_pass'])
				if ret:
					# Set session variables
					session['ht_user'] = request.form['ht_user']
					session['ht_profileid'] = ht_profile['profile_id']
					session['ht_api_object'] = hx_api_object.serialize()
					
					# Decrypt background processor credential if available
					# TODO: this could probably be better written
					iv = None
					salt = crypt_generate_random(32)
					background_credential = ht_db.backgroundProcessorCredentialGet(ht_profile['profile_id'])
					if background_credential:
						salt = HXAPI.b64(background_credential['salt'], True)
						iv = HXAPI.b64(background_credential['iv'], True)
						
					key = crypt_pbkdf2_hmacsha256(salt, request.form['ht_pass'])
					
					if iv and salt:
						try:
							decrypted_background_password = crypt_aes(key, iv, background_credential['hx_api_encrypted_password'], decrypt = True)
							start_background_processor(ht_profile['profile_id'], background_credential['hx_api_username'], decrypted_background_password)
						except UnicodeDecodeError:
							app.logger.error("Failed to decrypt background processor credential! Did you recently change your password? If so, please unset and reset these credentials under Settings.")
						finally:
							decrypted_background_password = None

					session['key']= HXAPI.b64(key)
					session['salt'] = HXAPI.b64(salt)

					app.logger.info("Successful Authentication - User: %s@%s:%s", session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
					redirect_uri = request.args.get('redirect_uri')
					if not redirect_uri:
						redirect_uri = "/?time=week"
					return redirect(redirect_uri, code=302)
				else:
					return render_template('ht_login.html', fail=response_data)		
		return render_template('ht_login.html', hx_default_port = HXAPI.HX_DEFAULT_PORT, fail = "Invalid profile id.")
	else:	
		return render_template('ht_login.html', hx_default_port = HXAPI.HX_DEFAULT_PORT)
		
@app.route('/logout', methods=['GET'])
def logout():
	if session and session['ht_api_object']:
		hx_api_object = HXAPI.deserialize(session['ht_api_object'])
		hx_api_object.restLogout()	
		app.logger.info('User logged out: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		session.pop('ht_user', None)
		session.pop('ht_api_object', None)
		hx_api_object = None
	return redirect("/login", code=302)
	

####################################
#
#	HXTool API
#	
####################################	
	
####################
# Profile Management
####################
@app.route('/api/v{0}/profile'.format(HXTOOL_API_VERSION), methods=['GET', 'PUT'])
def profile():
	if request.method == 'GET':
		profiles = ht_db.profileList()
		return json.dumps({'data_count' :  len(profiles), 'data' : profiles})
	elif request.method == 'PUT':
		request_json = request.json
		if validate_json(['hx_name', 'hx_host', 'hx_port'], request_json):
			if ht_db.profileCreate(request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				app.logger.info("New controller profile added")
				return make_response_by_code(200)
		else:
			return make_response_by_code(400)
			
@app.route('/api/v{0}/profile/<profile_id>'.format(HXTOOL_API_VERSION), methods=['GET', 'PUT', 'DELETE'])
def profile_by_id(profile_id):
	if request.method == 'GET':
		profile_object = ht_db.profileGet(profile_id)
		if profile_object:
			return json.dumps({'data' : profile_object})
		else:
			return make_response_by_code(404)
	elif request.method == 'PUT':
		request_json = request.json
		if validate_json(['profile_id', 'hx_name', 'hx_host', 'hx_port'], request_json):
			if ht_db.profileUpdate(request_json['_id'], request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				app.logger.info("Controller profile %d modified.", profile_id)
				return make_response_by_code(200)
	elif request.method == 'DELETE':
		if ht_db.profileDelete(profile_id):
			app.logger.info("Controller profile %s deleted.", profile_id)
			return make_response_by_code(200)
		else:
			return make_response_by_code(404)

#####################
# Stacking Results
#####################
@app.route('/api/v{0}/stacking/<int:stack_id>/results'.format(HXTOOL_API_VERSION), methods=['GET'])
@valid_session_required
def stack_job_results(hx_api_object, stack_id):
	stack_job = ht_db.stackJobGetById(stack_id)
	
	if stack_job is None:
		return make_response_by_code(404)

	if session['ht_profileid'] != stack_job['profile_id']:
		return make_response_by_code(401)
		
	ht_data_model = hxtool_data_models(stack_job['stack_type'])
	return ht_data_model.stack_data(stack_job['results'])	
		
		
####################
# Utility Functions
####################

def validate_json(keys, j):
	for k in keys:
		if not k in j or not j[k]:
			return False	
	return True
		
def make_response_by_code(code):
	code_table = {200 : {'message' : 'OK'},
				400 : {'message' : 'Invalid request'},
				404 : {'message' : 'Object not found'}}
	return (json.dumps(code_table.get(code)), code)

"""
Generate a random byte string for use in encrypting the background processor credentails
"""
def crypt_generate_random(length):
	return os.urandom(length)

"""
Return a PBKDF2 HMACSHA256 digest of a salt and password
"""
def crypt_pbkdf2_hmacsha256(salt, data):
	return PBKDF2(data, salt, dkLen = 32, count = 100000, prf = lambda p, s: HMAC.new(p, s, SHA256).digest())

"""
AES-256 operation
"""
def crypt_aes(key, iv, data, decrypt = False, base64_coding = True):
	cipher = AES.new(key, AES.MODE_OFB, iv)
	if decrypt:
		if base64_coding:
			data = HXAPI.b64(data, True)
		data = cipher.decrypt(data).decode('utf-8')
		# Implement PKCS7 de-padding
		pad_length = ord(data[-1:])
		if 1 <= pad_length <= 15:
			if all(c == chr(pad_length) for c in data[-pad_length:]):
				data = data[:len(data) - pad_length:]
		return data
	else:
		# Implement PKCS7 padding
		pad_length = 16 - (len(data) % 16)
		if pad_length < 16:
			data += (chr(pad_length) * pad_length)
		data = data.encode('utf-8')			
		data = cipher.encrypt(data)
		if base64_coding:
			data = HXAPI.b64(data)
		return data
	
"""
Iter over a Requests response object
and yield the chunk
"""
def iter_chunk(r, chunk_size = 1024):
	for chunk in r.iter_content(chunk_size = chunk_size):
		yield chunk
	
### background processing 
#################################
def start_background_processor(profile_id, hx_api_username, hx_api_password):
	p = hxtool_background_processor(ht_config, ht_db, profile_id, logger = app.logger)
	if p.start(hx_api_username, hx_api_password):
		app.logger.info('Background processor started.')
	else:
		p = None
		
###########
### Main ####
###########			
		
if __name__ == "__main__":
	app.secret_key = crypt_generate_random(32)
			
	app.logger.setLevel(logging.INFO)
	
	# Log early init/failures to stdout
	console_log = logging.StreamHandler(sys.stdout)
	console_log.setFormatter(logging.Formatter('[%(asctime)s] {%(module)s} {%(threadName)s} %(levelname)s - %(message)s'))
	app.logger.addHandler(console_log)
	
	ht_config = hxtool_config('conf.json', logger = app.logger)
	
	# Initialize configured log handlers
	for log_handler in ht_config.log_handlers():
		app.logger.addHandler(log_handler)

	# WSGI request log - when not running under gunicorn or mod_wsgi
	logger = logging.getLogger('werkzeug')
	if logger:
		logger.setLevel(logging.INFO)
		request_log_handler = logging.handlers.RotatingFileHandler('log/access.log', maxBytes=50000, backupCount=5)
		request_log_formatter = logging.Formatter("[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s")
		request_log_handler.setFormatter(request_log_formatter)	
		logger.addHandler(request_log_handler)

	# Start
	app.logger.info('Application starting')

	# Init DB
	ht_db = hxtool_db('hxtool.db', logger = app.logger)
	
	if ht_config['network']['ssl'] == "enabled":
		context = (ht_config['ssl']['cert'], ht_config['ssl']['key'])
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'], ssl_context=context, threaded=True)
	else:
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'])
