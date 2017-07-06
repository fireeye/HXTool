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

import logging

from functools import wraps
from flask import Flask, request, session, redirect, render_template, send_file, g, url_for

from hx_lib import *

from hxtool_formatting import *
from hxtool_db import *
from hxtool_process import *
from hxtool_config import *

import base64
import json
import io
import os

import datetime
import StringIO
import threading
import time
import sys
reload(sys)
sys.setdefaultencoding('utf8')

app = Flask(__name__, static_url_path='/static')

ht_config = None
ht_db = None

def valid_session_required(f):
	@wraps(f)
	def is_session_valid(*args, **kwargs):
		if not (session and 'ht_user' in session and 'ht_api_object' in session):
			return redirect(url_for('login', redirect_uri = request.path[1:]))
		else:
			o = HXAPI.deserialize(session['ht_api_object'])
			if o.restIsSessionValid():	
				kwargs['hx_api_object'] = o
			else:
				app.logger.info('The HX API token for the current session has expired, redirecting to the login page.')
				return redirect(url_for('login', redirect_uri = request.path[1:]))
				
		return f(*args, **kwargs)
	return is_session_valid

# Dashboard page
################

@app.route('/')
@valid_session_required
def index(hx_api_object):
	if not 'render' in request.args:
		return render_template('ht_index_ph.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
	else:
	
		if 'time' in request.args:
			mytime = request.args.get('time')
			if mytime == "today":
				starttime = datetime.datetime.now()
			elif mytime == "week":
				starttime = datetime.datetime.now() - datetime.timedelta(days=7)
			elif mytime == "2weeks":
				starttime = datetime.datetime.now() - datetime.timedelta(days=14)
			elif mytime == "30days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=30)
			elif mytime == "60days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=60)
			elif mytime == "90days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=90)
			elif mytime == "182days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=182)
			elif mytime == "365days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=365)
			else:
				starttime = datetime.datetime.now() - datetime.timedelta(days=7)
		else:
			mytime = "week"
			starttime = datetime.datetime.now() - datetime.timedelta(days=7)

		interval_select = ""
		for i in ["today", "week", "2weeks", "30days", "60days", "90days", "182days", "365days"]:
				interval_select += '<option value="/?time={0}"{1}>{2}</option>'.format(i, ' selected="selected"' if i == mytime else '', i)
			
		base = datetime.datetime.today()
	
		(ret, response_code, response_data) = hx_api_object.restGetAlertsTime(starttime.strftime("%Y-%m-%d"), base.strftime("%Y-%m-%d"))
		
		nr_of_alerts = len(response_data)
		
		# Recent alerts
		alerts = formatDashAlerts(response_data, hx_api_object)

		if nr_of_alerts > 0:
			stats = [{'value': 0, 'label': 'Exploit'}, {'value': 0, 'label': 'IOC'}, {'value': 0, 'label': 'Malware'}]
			for alert in response_data:
				if alert['source'] == "EXD":
					stats[0]['value'] = stats[0]['value'] + 1
				if alert['source'] == "IOC":
					stats[1]['value'] = stats[1]['value'] + 1
				if alert['source'] == "MAL":
					stats[2]['value'] = stats[2]['value'] + 1
			
			stats[0]['value'] = round((stats[0]['value'] / float(nr_of_alerts)) * 100)
			stats[1]['value'] = round((stats[1]['value'] / float(nr_of_alerts)) * 100)
			stats[2]['value'] = round((stats[2]['value'] / float(nr_of_alerts)) * 100)
		else:
			stats = [{'value': 0, 'label': 'Exploit'}, {'value': 0, 'label': 'IOC'}, {'value': 0, 'label': 'Malware'}]

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

		contcounter = 0;
		hostcounter = 0;
		searchcounter = 0;
		for entry in response_data['data']['entries']:
			hostcounter = hostcounter + 1
			if entry['containment_state'] != "normal":
				contcounter = contcounter + 1

		(ret, response_code, response_data) = hx_api_object.restListSearches()
		for entry in response_data['data']['entries']:
						if entry['state'] == "RUNNING":
								searchcounter = searchcounter + 1;

		(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
		blkcounter = 0;
		for entry in response_data['data']['entries']:
			if entry['state'] == "RUNNING":
				blkcounter = blkcounter + 1;

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


### Alerts Page
###################

@app.route('/alerts', methods=['GET', 'POST'])
@valid_session_required
def alerts(hx_api_object):
		
	if request.method == "POST":
		# We have a new annotation
		if 'annotateText' in request.form:
			# Create entry in the alerts table
			newrowid = sqlAddAlert(c, conn, session['ht_profileid'], request.form['annotateId'])
			# Add annotation to annotation table
			sqlAddAnnotation(c, conn, newrowid, request.form['annotateText'], request.form['annotateState'], session['ht_user'])
			app.logger.info('New annotation - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return redirect("/alerts", code=302)
	
	if not 'render' in request.args:
		return render_template('ht_alerts_ph.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
	else:
		if 'acount' in request.args:
			acount = request.args['acount']
		else:
			acount = 50
	
		acountselect = ""
		for i in [10, 20, 30, 50, 100, 250, 500, 1000]:
			acountselect += '<option value="/alerts?acount={0}"{1}>Last {2} Alerts</option>'.format(i, ' selected="selected"' if i == int(acount) else '', i)
				
		(ret, response_code, response_data) = hx_api_object.restGetAlerts(str(acount))
		alertshtml = formatAlertsTable(response_data, hx_api_object, session['ht_profileid'], c, conn)
		return render_template('ht_alerts.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), alerts=alertshtml, acountselect=acountselect)
		
@app.route('/annotatedisplay', methods=['GET'])
@valid_session_required
def annotatedisplay(hx_api_object):	
	if 'alertid' in request.args:
		an = sqlGetAnnotations(c, conn, request.args.get('alertid'), session['ht_profileid'])
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
		b64ioc = base64.b64encode(rawioc)
		(ret, response_code, response_data) = hx_api_object.restSubmitSweep(b64ioc, request.form['sweephostset'])
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
def searchaction():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		if request.args.get('action') == "stop":
			(ret, response_code, response_data) = hx_api_object.restCancelJob('/hx/api/v2/searches/', request.args.get('id'))
			app.logger.info('User access: Enterprise Search action STOP - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return redirect("/search", code=302)
			
		if request.args.get('action') == "remove":
			(ret, response_code, response_data) = hx_api_object.restDeleteJob('/hx/api/v2/searches/', request.args.get('id'))
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
		
		strIO = StringIO()
		strIO.write(ioclist_json)
		strIO.seek(0)
		app.logger.info('Indicator(s) exported - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return send_file(strIO, attachment_filename=iocfname, as_attachment=True)

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
			myplatforms = iocs[iockey]['platforms'].split(",")
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
		(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(bulk_acquisition_script, request.form['bulkhostset'])
		app.logger.info('New bulk acquisition - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)

	conn = sqlite3.connect('hxtool.db')
	c = conn.cursor()
	(ret, response_code, response_data) = hx_api_object.restListBulkAcquisitions()
	bulktable = formatBulkTable(c, conn, response_data, session['ht_profileid'])
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	return render_template('ht_bulk.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable, hostsets=hostsets)
	
@app.route('/bulkdetails')
@valid_session_required
def bulkdetails(hx_api_object):
	if request.args.get('id'):

		(ret, response_code, response_data) = hx_api_object.restListBulkDetails(request.args.get('id'))
		bulktable = formatBulkHostsTable(response_data)

		return render_template('ht_bulk_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable)



@app.route('/bulkdownload')
@valid_session_required
def bulkdownload(hx_api_object):
	if request.args.get('id'):
		urlhead, fname = os.path.split(request.args.get('id'))
		(ret, response_code, response_data) = hx_api_object.restDownloadBulkAcq(request.args.get('id'))
		app.logger.info('Bulk acquisition download - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return send_file(io.BytesIO(response_data), attachment_filename=fname, as_attachment=True)

				
@app.route('/bulkaction', methods=['GET'])
@valid_session_required
def bulkaction(hx_api_object):

	if request.args.get('action') == "stop":
		(ret, response_code, response_data) = hx_api_object.restCancelJob('/hx/api/v2/acqs/bulk/', request.args.get('id'))
		app.logger.info('Bulk acquisition action STOP - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
		
	if request.args.get('action') == "remove":
		(ret, response_code, response_data) = hx_api_object.restDeleteJob('/hx/api/v2/acqs/bulk/', request.args.get('id'))
		app.logger.info('Bulk acquisition action REMOVE - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)	
		
	if request.args.get('action') == "download":
		res = sqlAddBulkDownload(c, conn, session['ht_profileid'], request.args.get('id'))
		app.logger.info('Bulk acquisition action DOWNLOAD - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/bulk", code=302)
		
	if request.args.get('action') == "stopdownload":
		res = sqlRemoveBulkDownload(c, conn, session['ht_profileid'], request.args.get('id'))
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

### Stacking
##########
@app.route('/stacking', methods=['GET', 'POST'])
@valid_session_required
def stacking(hx_api_object):
	
	if request.args.get('stop'):
		sqlChangeStackJobState(c, conn, request.args.get('stop'), session['ht_profileid'], "STOPPING")
		app.logger.info('Data stacking action STOP - User: {0}@{1}:{2}'.format(session['ht_user'], session['ht_ip'], session['ht_port']))
		return redirect("/stacking", code=302)

	if request.args.get('remove'):
		sqlChangeStackJobState(c, conn, request.args.get('remove'), session['ht_profileid'], "REMOVING")
		app.logger.info('Data stacking action REMOVE - User: {0}@{1}:{2}'.format(session['ht_user'], session['ht_ip'], session['ht_port']))
		return redirect("/stacking", code=302)

		
	if request.method == 'POST':
		out = sqlAddStackJob(c, conn, session['ht_profileid'], request.form['stacktype'], request.form['stackhostset'])
		app.logger.info('New data stacking job - User: {0}@{1}:{2}'.format(session['ht_user'], session['ht_ip'], session['ht_port']))
	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsets(response_data)
	
	stacktable = formatStackTable(c, conn, session['ht_profileid'], response_data)
	
	return render_template('ht_stacking.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable, hostsets=hostsets)


@app.route('/stackinganalyze', methods=['GET', 'POST'])
@valid_session_required
def stackinganalyze(hx_api_object):
	
	stackid = request.args.get('id')
	
	stackdata = sqlGetServiceMD5StackData(c, conn, stackid)
	stacktable = formatServiceMD5StackData(stackdata)
	
	return render_template('ht_stacking_analyze_svcmd5.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable)
		
			
### Settings
############
			
@app.route('/settings', methods=['GET', 'POST'])
@valid_session_required
def settings(hx_api_object):
	if request.method == 'POST':
		out = ht_db.backgroundProcessorCredentialsSet(session['ht_profileid'], request.form['bguser'], request.form['bgpass'])
		app.logger.info("Background Processing credentials set profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	
	if request.args.get('unset'):
		out = ht_db.backgroundProcessorCredentialsUnset(session['ht_profileid'])
		app.logger.info("Background Processing credentials unset profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
		return redirect("/settings", code=302)
	
	bgcreds = formatProfCredsInfo(ht_db.backgroundProcessorCredentialsExist(session['ht_profileid']))
	
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
			ht_profile = ht_db.profileGetById(request.form['controllerProfileDropdown'])
			if ht_profile:	
				hx_api_object = HXAPI(ht_profile['hx_host'], hx_port = ht_profile['hx_port'], headers = ht_config.get_or_none('headers'), cookies = ht_config.get_or_none('cookies'), logger = app.logger)
				
				(ret, response_code, response_data) = hx_api_object.restLogin(request.form['ht_user'], request.form['ht_pass'])
				if ret:
					# Set session variables
					session['ht_user'] = request.form['ht_user']
					session['ht_profileid'] = ht_profile['_id']
					app.logger.info("Successful Authentication - User: %s@%s:%s", session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
					session['ht_api_object'] = hx_api_object.serialize()
					redirect_uri = request.args.get('redirect_uri')
					if not redirect_uri:
						redirect_uri = "/?time=week"
					return redirect(redirect_uri, code=302)
				else:
					return render_template('ht_login.html', fail=response_data)
			else:
				return render_template('ht_login.html', fail = 'Invalid profile id.')
	else:	
		return render_template('ht_login.html')
		
@app.route('/logout', methods=['GET'])
@valid_session_required
def logout(hx_api_object):
	hx_api_object.restLogout()	
	app.logger.info('User logged out: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	session.pop('ht_user', None)
	session.pop('ht_api_object', None)
	hx_api_object = None
	return redirect("/login", code=302)
	

####################
# Profile Management
####################
@app.route('/profile', methods=['GET', 'POST'])
def profile():
	if request.method == 'GET':
		profiles = ht_db.profileList()
		return json.dumps({'data_count' :  len(profiles), 'data' : profiles})
	elif request.method == 'POST':
		request_json = request.json
		if ['hx_name', 'hx_host', 'hx_port'] in request_json:
			if hx_db.profileCreate(request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				return make_response_by_code(200)
		else:
			return make_response_by_code(400)
			
@app.route('/profile/<int:profile_id>', methods=['GET', 'POST', 'DELETE'])
def profile_by_id(profile_id):
	if request.method == 'GET':
		profile_object = ht_db.profileGetById(profile_id)
		if profile_object:
			return json.dumps({'data' : profile_object})
		else:
			return make_response_by_code(404)
	elif request.method == 'POST':
		request_json = request.json
		if ['_id', 'hx_name', 'hx_host', 'hx_port'] in request_json:
			if hx_db.profileUpdateById(request_json['_id'], request_json['hx_name'], request_json['hx_host'], request_json['hx_port']):
				return make_response_by_code(200)
	elif request.method == 'DELETE':
		if ht_db.profileDeleteById(profile_id):
			return make_response_by_code(200)
		else:
			return make_response_by_code(404)
			
		
####################
# Utility Functions
####################


def is_session_valid(session):
	if session and 'ht_user' in session and 'ht_api_object' in session:
		hx_api_object = HXAPI.deserialize(session['ht_api_object'])
		return(hx_api_object.restIsSessionValid(), hx_api_object)
	else:
		return(False, None)
		
def make_response_by_code(code):
	code_table = {200 : {'message' : 'OK'},
				400 : {'message' : 'Invalid request'},
				404 : {'message' : 'Object not found'}}
	return (json.dumps(code_table.get(code)), code)	
	
### Thread: background processing 
#################################
		
def bgprocess(bgprocess_config):
	
	time.sleep(1)
	app.logger.info('Background processor thread started')
	# SQLITE3
	conn = sqlite3.connect('hxtool.db')
	c = conn.cursor()
	
	while True:
		try:
			backgroundStackProcessor(c, conn, bgprocess_config, app)
		except BaseException as e:
			print('{!r}; StackProcessor error'.format(e))
		
		try:
			backgroundBulkProcessor(c, conn, bgprocess_config, app)
		except BaseException as e:
			print('{!r}; BulkProcessor error'.format(e))
			
		time.sleep(bgprocess_config['background_processor']['poll_interval'])
		
		
###########
### Main ####
###########			

app.secret_key = 'A0Zr98j/3yX23R~XH1212jmN]Llw/,?RT'
		
if __name__ == "__main__":
	
	app.logger.setLevel(logging.INFO)
	
	# Log early init/failures to stdout
	console_log = logging.StreamHandler(sys.stdout)
	console_log.setFormatter(logging.Formatter('[%(asctime)s] {%(module)s} {%(threadName)s} %(levelname)s - %(message)s'))
	app.logger.addHandler(console_log)
	
	ht_config = hxtool_config('conf.json', logger=app.logger)
	
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
	ht_db = hxtool_db('hxtool.db')
	
	# Start background processing thread
	#thread = threading.Thread(target=bgprocess, name='BackgroundProcessorThread', args=(ht_config,))
	#thread.daemon = True
	#thread.start()
	#app.logger.info('Background Processor thread starting')
	
	if ht_config['network']['ssl'] == "enabled":
		context = (ht_config['ssl']['cert'], ht_config['ssl']['key'])
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'], ssl_context=context, threaded=True)
	else:
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'])
