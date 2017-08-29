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
from logging.handlers import RotatingFileHandler
from flask import Flask, request, session, redirect, render_template, send_file
from hx_lib import *
from hxtool_formatting import *
import base64
import json
import io
import os
import sqlite3
from hxtool_db import *
import datetime
import StringIO
import threading
import time
from hxtool_process import *
from hxtool_config import *
import sys

reload(sys)
sys.setdefaultencoding('utf8')

conn = sqlite3.connect('hxtool.db')
c = conn.cursor()

sqlCreateTables(c)

app = Flask(__name__, static_url_path='/static')

ht_config = None

# Dashboard page
################

@app.route('/')
def index():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		
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
			
	else:
		return redirect("/login", code=302)


### Hosts
##########

@app.route('/hosts', methods=['GET', 'POST'])
def hosts():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
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
				print response_data
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
			
	else:
		return redirect("/login", code=302)


### Triage popup
@app.route('/triage', methods=['GET'])
def triage():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		triageid= request.args.get('host')
		url = request.args.get('url')
		mytime = datetime.datetime.now()
		return render_template('ht_triage.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), triageid=triageid, url=url, now=mytime.strftime('%Y-%m-%d %H:%M:%S'))

		
### File acquisition popup
@app.route('/fileaq', methods=['GET'])
def fileaq():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		hostid = request.args.get('host')
		url = request.args.get('url')
		return render_template('ht_fileaq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostid=hostid, url=url)

		
### Acquisition popup
@app.route('/acq', methods=['GET'])
def acq():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		hostid = request.args.get('host')
		url = request.args.get('url')
		return render_template('ht_acq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostid=hostid, url=url)
		
### Alerts Page
###################

@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
			
		if request.method == "POST":
			# We have a new annotation
			if 'annotateText' in request.form:
				# Create entry in the alerts table
				newrowid = sqlAddAlert(c, conn, session['ht_profileid'], request.form['annotateId'])
				# Add annotation to annotation table
				sqlAddAnnotation(c, conn, newrowid, request.form['annotateText'], request.form['annotateState'], session['ht_user'])
				app.logger.info('New annotation - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				return redirect("/alerts?acount=30", code=302)
		
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
	else:
		return redirect("/login", code=302)

		
@app.route('/annotatedisplay', methods=['GET'])
def annotatedisplay():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
		
		if 'alertid' in request.args:
			an = sqlGetAnnotations(c, conn, request.args.get('alertid'), session['ht_profileid'])
			annotatetable = formatAnnotationTable(an)
	
		return render_template('ht_annotatedisplay.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), annotatetable=annotatetable)
	else:
		return redirect("/login", code=302)



#### Enterprise Search
#########################

@app.route('/search', methods=['GET', 'POST'])
def search():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
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
	else:
		return redirect("/login", code=302)

@app.route('/searchresult', methods=['GET'])
def searchresult():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		if request.args.get('id'):
			(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'))
			res = formatSearchResults(response_data)
			return render_template('ht_search_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), result=res)
	else:
		return redirect("/login", code=302)

			
@app.route('/searchaction', methods=['GET'])
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
		
	else:
		return redirect("/login", code=302)


#### Build a real-time indicator
####################################

@app.route('/buildioc', methods=['GET', 'POST'])
def buildioc():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		
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
	else:
		return redirect("/login", code=302)


### Manage Indicators
#########################

@app.route('/indicators', methods=['GET', 'POST'])
def indicators():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
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
	else:
		return redirect("/login", code=302)

@app.route('/indicatorcondition')
def indicatorcondition():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		uuid = request.args.get('uuid')
		category = request.args.get('category')
	
		(ret, response_code, condition_class_presence) = hx_api_object.restGetCondition(category, uuid, 'presence')
		(ret, response_code, condition_class_execution) = hx_api_object.restGetCondition(category, uuid, 'execution')
		
		conditions = formatConditions(condition_class_presence, condition_class_execution)
	
		return render_template('ht_indicatorcondition.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), conditions=conditions)
	else:
		return redirect("/login", code=302)
		

@app.route('/categories', methods=['GET', 'POST'])
def categories():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		if request.method == 'POST':
			catname = request.form.get('catname')
			(ret, response_code, response_data) = hx_api_object.restCreateCategory(str(catname))
			app.logger.info('New indicator category created - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	
	
		(ret, response_code, response_data) = hx_api_object.restListIndicatorCategories()
		categories = formatCategories(response_data)
		
		return render_template('ht_categories.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), categories=categories)
	else:
		return redirect("/login", code=302)

@app.route('/import', methods=['POST'])
def importioc():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		
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
	else:
		return redirect("/login", code=302)


### Bulk Acqusiitions
#########################

@app.route('/bulk', methods=['GET', 'POST'])
def listbulk():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
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
	else:
		return redirect("/login", code=302)

@app.route('/bulkdetails')
def bulkdetails():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:

		if request.args.get('id'):

			(ret, response_code, response_data) = hx_api_object.restListBulkDetails(request.args.get('id'))
			bulktable = formatBulkHostsTable(response_data)

			return render_template('ht_bulk_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bulktable=bulktable)
	else:
			return redirect("/login", code=302)


@app.route('/bulkdownload')
def bulkdownload():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		if request.args.get('id'):
			urlhead, fname = os.path.split(request.args.get('id'))
			(ret, response_code, response_data) = hx_api_object.restDownloadBulkAcq(request.args.get('id'))
			app.logger.info('Bulk acquisition download - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			return send_file(io.BytesIO(response_data), attachment_filename=fname, as_attachment=True)
	else:
			return redirect("/login", code=302)

			
@app.route('/download')
def download():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		if request.args.get('id'):
			urlhead, fname = os.path.split(request.args.get('id'))
			(ret, response_code, response_data) = hx_api_object.restDownloadGeneric(request.args.get('id'))
			if ret:
				app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('id'))
				return send_file(io.BytesIO(response_data), attachment_filename=fname, as_attachment=True)
			else:
				print response_data
	else:
			return redirect("/login", code=302)
				

@app.route('/bulkaction', methods=['GET'])
def bulkaction():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
	
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
	else:
		return redirect("/login", code=302)

				
### Reports
############

@app.route('/reports')
def reports():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		return render_template('ht_reports.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
	else:
		return redirect("/login", code=302)

@app.route('/reportgen')
def reportgen():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
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
		else:
			return redirect("/login", code=302)

### Stacking
##########
@app.route('/stacking', methods=['GET', 'POST'])
def stacking():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:

			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()			
			
			if request.args.get('stop'):
				sqlChangeStackJobState(c, conn, request.args.get('stop'), session['ht_profileid'], "STOPPING")
				app.logger.info('Data stacking action STOP - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
				return redirect("/stacking", code=302)

			if request.args.get('remove'):
				sqlChangeStackJobState(c, conn, request.args.get('remove'), session['ht_profileid'], "REMOVING")
				app.logger.info('Data stacking action REMOVE - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
				return redirect("/stacking", code=302)

				
			if request.method == 'POST':
				out = sqlAddStackJob(c, conn, session['ht_profileid'], request.form['stacktype'], request.form['stackhostset'])
				app.logger.info('New data stacking job - User: {0}@{1}:{2}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
			
			(ret, response_code, response_data) = hx_api_object.restListHostsets()
			hostsets = formatHostsets(response_data)
			
			stacktable = formatStackTable(c, conn, session['ht_profileid'], response_data)
			
			return render_template('ht_stacking.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable, hostsets=hostsets)
	else:
			return redirect("/login", code=302)

@app.route('/stackinganalyze', methods=['GET', 'POST'])
def stackinganalyze():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
		
		stackid = request.args.get('id')
		
		stackdata = sqlGetServiceMD5StackData(c, conn, stackid)
		stacktable = formatServiceMD5StackData(stackdata)
		
		return render_template('ht_stacking_analyze_svcmd5.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), stacktable=stacktable)
	else:
		return redirect("/login", code=302)
		
			
### Settings
############
			
@app.route('/settings', methods=['GET', 'POST'])
def settings():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
	
			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()
	
			if (request.method == 'POST'):
				out = sqlInsertProfCredsInfo(c, conn, session['ht_profileid'], request.form['bguser'], request.form['bgpass'])
				app.logger.info("Background Processing credentials set profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			
			if request.args.get('unsetprofcreds'):
				out = sqlDeleteProfCredsInfo(c, conn, session['ht_profileid'])
				app.logger.info("Background Processing credentials unset profileid: %s by user: %s@%s:%s", session['ht_profileid'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				return redirect("/settings", code=302)
			
			bgcreds = formatProfCredsInfo(c, conn, session['ht_profileid'])
			
			return render_template('ht_settings.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), bgcreds=bgcreds)
	else:
			return redirect("/login", code=302)

			
### Custom Configuration Channels
########################
@app.route('/channels', methods=['GET', 'POST'])
def channels():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		(ret, response_code, response_data) = hx_api_object.restCheckAccessCustomConfig()
		if ret:
			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()
	
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
	else:
			return redirect("/login", code=302)

@app.route('/channelinfo', methods=['GET'])
def channelinfo():
	(ret, hx_api_object) = is_session_valid(session)
	if ret:
		(ret, response_code, response_data) = hx_api_object.restCheckAccessCustomConfig()
		if ret:
			# TODO: finish
			(ret, response_code, response_data) = hx_api_object.restGetConfigChannelConfiguration(request.args.get('id'))
			return render_template('ht_configchannel_info.html', channel_json = json.dumps(response_data, sort_keys = True, indent = 4))
		else:
			return render_template('ht_noaccess.html')
	else:
			return redirect("/login", code=302)
			
#### Authentication
#######################

@app.route('/login', methods=['GET', 'POST'])
def login():

	conn = sqlite3.connect('hxtool.db')
	c = conn.cursor()
	
	if (request.method == 'POST'):
		if 'ht_user' in request.form:
			(profile_id, hx_host) = request.form['ht_ip'].split("__")
			hx_port = HXAPI.HX_DEFAULT_PORT
			if ':' in hx_host:
				hx_host_port = hx_host.split(':')
				hx_host = hx_host_port[0]
				if 0 < int(hx_host_port[1]) <= 65535:
					hx_port = hx_host_port[1]
				
			hx_api_object = HXAPI(hx_host, hx_port = hx_port, headers = ht_config.get_or_none('headers'), cookies = ht_config.get_or_none('cookies'), logger = app.logger)
			
			(ret, response_code, response_data) = hx_api_object.restLogin(request.form['ht_user'], request.form['ht_pass'])
			if ret:
				# Set session variables
				session['ht_user'] = request.form['ht_user']
				session['ht_profileid'] = profile_id
				app.logger.info("Successful Authentication - User: %s@%s:%s", session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				session['ht_api_object'] = hx_api_object.serialize()
				return redirect("/?time=week", code=302)
			else:
				options = ""
				for profile in sqlGetProfiles(c):
					options += "<option value='" + str(profile[0]) + "__" + profile[2] + "'>" + profile[1] + " - " + profile[2]
				return render_template('ht_login.html', fail=response_data, controllers=options)
			
		elif 'cname' in request.form:
			message = "New profile created"
			
			sqlAddProfileItem(c, conn, request.form['cname'], request.form['chostname'])
			app.logger.info("New controller profile added")
			
			options = ""
			for profile in sqlGetProfiles(c):
				options += "<option value='" + str(profile[0]) + "__" + profile[2] + "'>" + profile[1] + " - " + profile[2]

			return render_template('ht_login.html', fail=message, controllers=options)

	else:
		options = ""
		for profile in sqlGetProfiles(c):
			options += "<option value='" + str(profile[0]) + "__" + profile[2] + "'>" + profile[1] + " - " + profile[2]

		return render_template('ht_login.html', controllers=options)


@app.route('/logout')
def logout():
	hx_api_object = HXAPI.deserialize(session['ht_api_object'])
	app.logger.info('User logged out: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
	session.pop('ht_user', None)
	session.pop('ht_api_object', None)
	hx_api_object = None
	return redirect("/", code=302)

	
def is_session_valid(session):
	if session and 'ht_user' in session and 'ht_api_object' in session:
		hx_api_object = HXAPI.deserialize(session['ht_api_object'])
		return(hx_api_object.restIsSessionValid(), hx_api_object)
	else:
		return(False, None)

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
		request_log_handler = RotatingFileHandler('log/access.log', maxBytes=50000, backupCount=5)
		request_log_formatter = logging.Formatter("[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s")
		request_log_handler.setFormatter(request_log_formatter)	
		logger.addHandler(request_log_handler)

	# Start
	app.logger.info('Application starting')

	
	# Start background processing thread
	thread = threading.Thread(target=bgprocess, name='BackgroundProcessorThread', args=(ht_config,))
	thread.daemon = True
	thread.start()
	app.logger.info('Background Processor thread starting')
	
	if ht_config['network']['ssl'] == "enabled":
		context = (ht_config['ssl']['cert'], ht_config['ssl']['key'])
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'], ssl_context=context, threaded=True)
	else:
		app.run(host=ht_config['network']['listen_address'], port=ht_config['network']['port'])
