#!/usr/bin/python

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

# Dashboard page
################

@app.route('/')
def index():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		if 'time' in request.args:
			if request.args.get('time') == "today":
				starttime = datetime.datetime.now()
			elif request.args.get('time') == "week":
				starttime = datetime.datetime.now() - datetime.timedelta(days=7)
			elif request.args.get('time') == "2week":
				starttime = datetime.datetime.now() - datetime.timedelta(days=14)
			elif request.args.get('time') == "30days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=30)
			elif request.args.get('time') == "60days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=60)
			elif request.args.get('time') == "90days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=90)
			elif request.args.get('time') == "182days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=182)
			elif request.args.get('time') == "365days":
				starttime = datetime.datetime.now() - datetime.timedelta(days=365)
			else:
				starttime = datetime.datetime.now() - datetime.timedelta(days=7)
		else:
			starttime = datetime.datetime.now() - datetime.timedelta(days=7)
	
		base = datetime.datetime.today()
	
		alertsjson = restGetAlertsTime(session['ht_token'], starttime.strftime("%Y-%m-%d"), base.strftime("%Y-%m-%d"), session['ht_ip'], session['ht_port'])
		
		nr_of_alerts = len(alertsjson)
		
		# Recent alerts
		alerts = formatDashAlerts(alertsjson, session['ht_token'], session['ht_ip'], session['ht_port'])

		if nr_of_alerts > 0:
			stats = [{'value': 0, 'label': 'Exploit'}, {'value': 0, 'label': 'IOC'}, {'value': 0, 'label': 'Malware'}]
			for alert in alertsjson:
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
		
		for talert in alertsjson:

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
		hosts = restListHosts(session['ht_token'], session['ht_ip'], session['ht_port'])

		contcounter = 0;
		hostcounter = 0;
		searchcounter = 0;
		for entry in hosts['data']['entries']:
			hostcounter = hostcounter + 1
			if entry['containment_state'] != "normal":
				contcounter = contcounter + 1

		searches = restListSearches(session['ht_token'], session['ht_ip'], session['ht_port'])
		for entry in searches['data']['entries']:
                        if entry['state'] == "RUNNING":
                                searchcounter = searchcounter + 1;

		blk = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], session['ht_port'])
		blkcounter = 0;
		for entry in blk['data']['entries']:
			if entry['state'] == "RUNNING":
				blkcounter = blkcounter + 1;

		return render_template('ht_index.html', session=session, alerts=alerts, iocstats=stats, timeline=talerts_list, contcounter=str(contcounter), hostcounter=str(hostcounter), malcounter=str(malcounter), searchcounter=str(searchcounter), blkcounter=str(blkcounter), exdcounter=str(exdcounter), ioccounter=str(ioccounter))
	else:
		return redirect("/login", code=302)


### Jobdash
##########

@app.route('/jobdash', methods=['GET', 'POST'])
def jobdash():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):

		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
	
		blk = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], session['ht_port'])
		jobsBulk = formatBulkTableJobDash(c, conn, blk, session['ht_profileid'])

		s = restListSearches(session['ht_token'], session['ht_ip'], session['ht_port'])
		jobsEs = formatListSearchesJobDash(s)
		
		
		return render_template('ht_jobdash.html', session=session, jobsBulk=jobsBulk, jobsEs=jobsEs)
	else:
		return redirect("/login", code=302)


### Alerts Page
###################

@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
			
		if request.method == "POST":
			# We have a new annotation
			if 'annotateText' in request.form:
				# Create entry in the alerts table
				newrowid = sqlAddAlert(c, conn, session['ht_profileid'], request.form['annotateId'])
				# Add annotation to annotation table
				sqlAddAnnotation(c, conn, newrowid, request.form['annotateText'], request.form['annotateState'], session['ht_user'])
				app.logger.info('New annotation - User: ' + session['ht_user'] + "@" + session['ht_ip'])
		
		if 'acount' in request.args:
			acount = request.args['acount']
		else:
			acount = 50
		
		acountselect = ""
		for i in [10, 20, 30, 50, 100, 250, 500, 1000]:
			if (i == int(acount)):
				acountselect += "<option value='/alerts?acount=" + str(i) + "' selected='selected'>Last " + str(i) + " Alerts"
			else:
				acountselect += "<option value='/alerts?acount=" + str(i) + "'>Last " + str(i) + " Alerts"
		
		alerts = restGetAlerts(session['ht_token'], str(acount), session['ht_ip'], session['ht_port'])
		alertshtml = formatAlertsTable(alerts, session['ht_token'], session['ht_ip'], session['ht_port'], session['ht_profileid'], c, conn)
		
		return render_template('ht_alerts.html', session=session, alerts=alertshtml, acountselect=acountselect)

	else:
		return redirect("/login", code=302)

		
@app.route('/annotatedisplay', methods=['GET'])
def annotatedisplay():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
		
		if 'alertid' in request.args:
			an = sqlGetAnnotations(c, conn, request.args.get('alertid'), session['ht_profileid'])
			annotatetable = formatAnnotationTable(an)
	
		return render_template('ht_annotatedisplay.html', session=session, annotatetable=annotatetable)
	else:
		return redirect("/login", code=302)



#### Enterprise Search
#########################

@app.route('/search', methods=['GET', 'POST'])
def search():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		# If we get a post it's a new sweep
		if request.method == 'POST':
			f = request.files['newioc']
			rawioc = f.read()
			b64ioc = base64.b64encode(rawioc)
			out = restSubmitSweep(session['ht_token'], session['ht_ip'], session['ht_port'], b64ioc, request.form['sweephostset'])
			app.logger.info('New Enterprise Search - User: ' + session['ht_user'] + "@" + session['ht_ip'])

		s = restListSearches(session['ht_token'], session['ht_ip'], session['ht_port'])
		searches = formatListSearches(s)
		
		hs = restListHostsets(session['ht_token'], session['ht_ip'], session['ht_port'])
		hostsets = formatHostsets(hs)
		
		return render_template('ht_searchsweep.html', session=session, searches=searches, hostsets=hostsets)
	else:
		return redirect("/login", code=302)

@app.route('/searchresult', methods=['GET'])
def searchresult():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
			if request.args.get('id'):
				hostresults = restGetSearchResults(session['ht_token'], request.args.get('id'), session['ht_ip'], session['ht_port'])
				res = formatSearchResults(hostresults)
				return render_template('ht_search_dd.html', session=session, result=res)
        else:
                return redirect("/login", code=302)

				
@app.route('/searchaction', methods=['GET'])
def searchaction():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		if request.args.get('action') == "stop":
			res = restCancelJob(session['ht_token'], request.args.get('id'), '/hx/api/v2/searches/', session['ht_ip'], session['ht_port'])
			app.logger.info('User access: Enterprise Search action STOP - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/search", code=302)
			
		if request.args.get('action') == "remove":
			res = restDeleteJob(session['ht_token'], request.args.get('id'), '/hx/api/v2/searches/', session['ht_ip'], session['ht_port'])
			app.logger.info('User access: Enterprise Search action REMOVE - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/search", code=302)	
		
	else:
		return redirect("/login", code=302)


#### Build a real-time indicator
####################################

@app.route('/buildioc', methods=['GET', 'POST'])
def buildioc():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
		# New IOC to be created
		if request.method == 'POST':
		
			if request.form['platform'] == "all":
				myplatforms = ['win', 'osx']
			else:
				myplatforms = request.form['platform'].split(",")
				
			iocuri = restAddIndicator(session['ht_user'], request.form['iocname'], request.form['cats'], myplatforms, session['ht_token'], session['ht_ip'], session['ht_port'])
			app.logger.info('New indicator created - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			
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
				res = restAddCondition(iocuri, "presence", data, request.form['cats'], session['ht_token'], session['ht_ip'], session['ht_port'])

			for data in condEx:
                                data = """{"tests":[""" + data + """]}"""
                                data = data.replace('\\', '\\\\')
                                res = restAddCondition(iocuri, "execution", data, request.form['cats'], session['ht_token'], session['ht_ip'], session['ht_port'])


		categories = restListIndicatorCategories(session['ht_token'], session['ht_ip'], session['ht_port'])
		cats = formatCategoriesSelect(categories)
		return render_template('ht_buildioc.html', session=session, cats=cats)
	else:
		return redirect("/login", code=302)


### Manage Indicators
#########################

@app.route('/indicators', methods=['GET', 'POST'])
def indicators():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
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
				cond_ex = restGetCondition(session['ht_token'], 'execution', ioc['category'], ioc['uuid'], session['ht_ip'], session['ht_port'])
				for item in cond_ex['data']['entries']:
					ioclist[ioc['uuid']]['execution'].append(item['tests'])

				#Grab presence indicators
				cond_pre = restGetCondition(session['ht_token'], 'presence', ioc['category'], ioc['uuid'], session['ht_ip'], session['ht_port'])
				for item in cond_pre['data']['entries']:
					ioclist[ioc['uuid']]['presence'].append(item['tests'])
						
			ioclist_json = json.dumps(ioclist, indent=4)
			
			if len(iocs) == 1:
				iocfname = iocs[0]['name'] + ".ioc"
			else:
				iocfname = "multiple_indicators.ioc"
			
			strIO = StringIO()
			strIO.write(ioclist_json)
			strIO.seek(0)
			app.logger.info('Indicator(s) exported - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return send_file(strIO, attachment_filename=iocfname, as_attachment=True)
	
		iocs = restListIndicators(session['ht_token'], session['ht_ip'], session['ht_port'])
		indicators = formatIOCResults(iocs)
		return render_template('ht_indicators.html', session=session, indicators=indicators)
	else:
		return redirect("/login", code=302)

@app.route('/indicatorcondition')
def indicatorcondition():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		uuid = request.args.get('uuid')
		category = request.args.get('category')
	
		cond_pre = restGetCondition(session['ht_token'], 'presence', category, uuid, session['ht_ip'], session['ht_port'])
		cond_ex = restGetCondition(session['ht_token'], 'execution', category, uuid, session['ht_ip'], session['ht_port'])
		
		conditions = formatConditions(cond_pre, cond_ex)
	
		return render_template('ht_indicatorcondition.html', session=session, conditions=conditions)
	else:
		return redirect("/login", code=302)
		

@app.route('/categories', methods=['GET', 'POST'])
def categories():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		if request.method == 'POST':
			catname = request.form.get('catname')
			restCreateCategory(session['ht_token'], str(catname), session['ht_ip'], session['ht_port'])
			app.logger.info('New indicator category created - User: ' + session['ht_user'] + "@" + session['ht_ip'])
	
	
		cats = restListIndicatorCategories(session['ht_token'], session['ht_ip'], session['ht_port'])
		categories = formatCategories(cats)
		
		return render_template('ht_categories.html', session=session, categories=categories)
	else:
		return redirect("/login", code=302)

@app.route('/import', methods=['POST'])
def importioc():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
		if request.method == 'POST':
		
			fc = request.files['iocfile']				
			iocs = json.loads(fc.read())
			
			for iockey in iocs:
				myplatforms = iocs[iockey]['platforms'].split(",")
				iocuri = restAddIndicator(session['ht_user'], iocs[iockey]['name'], iocs[iockey]['category'], myplatforms, session['ht_token'], session['ht_ip'], session['ht_port'])

				for p_cond in iocs[iockey]['presence']:
					data = json.dumps(p_cond)
					data = """{"tests":""" + data + """}"""
					res = restAddCondition(iocuri, "presence", data, iocs[iockey]['category'], session['ht_token'], session['ht_ip'], session['ht_port'])

				for e_cond in iocs[iockey]['execution']:
					data = json.dumps(e_cond)
					data = """{"tests":""" + data + """}"""
					res = restAddCondition(iocuri, "execution", data, iocs[iockey]['category'], session['ht_token'], session['ht_ip'], session['ht_port'])
			
			app.logger.info('New indicator imported - User: ' + session['ht_user'] + "@" + session['ht_ip'])
		
		return redirect("/indicators", code=302)
	else:
		return redirect("/login", code=302)


### Bulk Acqusiitions
#########################

@app.route('/bulk', methods=['GET', 'POST'])
def listbulk():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
			if request.method == 'POST':
				f = request.files['bulkscript']
				bulkscript = f.read()
				newbulk = restNewBulkAcq(session['ht_token'], bulkscript, request.form['bulkhostset'], session['ht_ip'], session['ht_port'])
				app.logger.info('New bulk acquisition - User: ' + session['ht_user'] + "@" + session['ht_ip'])

			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()
			acqs = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], session['ht_port'])
			bulktable = formatBulkTable(c, conn, acqs, session['ht_profileid'])
			
			hs = restListHostsets(session['ht_token'], session['ht_ip'], session['ht_port'])
			hostsets = formatHostsets(hs)
			
			return render_template('ht_bulk.html', session=session, bulktable=bulktable, hostsets=hostsets)
        else:
			return redirect("/login", code=302)

@app.route('/bulkdetails')
def bulkdetails():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):

			if request.args.get('id'):

				hosts = restListBulkDetails(session['ht_token'], request.args.get('id'), session['ht_ip'], session['ht_port'])
				bulktable = formatBulkHostsTable(hosts)

				return render_template('ht_bulk_dd.html', session=session, bulktable=bulktable)
        else:
                return redirect("/login", code=302)


@app.route('/bulkdownload')
def bulkdownload():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
			if request.args.get('id'):
				urlhead, fname = os.path.split(request.args.get('id'))
				acq = restDownloadBulkAcq(session['ht_token'], request.args.get('id'), session['ht_ip'], session['ht_port'])
				app.logger.info('Bulk acquisition download - User: ' + session['ht_user'] + "@" + session['ht_ip'])
				return send_file(io.BytesIO(acq), attachment_filename=fname, as_attachment=True)
        else:
                return redirect("/login", code=302)

				
@app.route('/bulkaction', methods=['GET'])
def bulkaction():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
	
		if request.args.get('action') == "stop":
			res = restCancelJob(session['ht_token'], request.args.get('id'), '/hx/api/v2/acqs/bulk/', session['ht_ip'], session['ht_port'])
			app.logger.info('Bulk acquisition action STOP - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/bulk", code=302)
			
		if request.args.get('action') == "remove":
			res = restDeleteJob(session['ht_token'], request.args.get('id'), '/hx/api/v2/acqs/bulk/', session['ht_ip'], session['ht_port'])
			app.logger.info('Bulk acquisition action REMOVE - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/bulk", code=302)	
			
		if request.args.get('action') == "download":
			res = sqlAddBulkDownload(c, conn, session['ht_profileid'], request.args.get('id'))
			app.logger.info('Bulk acquisition action DOWNLOAD - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/bulk", code=302)
			
		if request.args.get('action') == "stopdownload":
			res = sqlRemoveBulkDownload(c, conn, session['ht_profileid'], request.args.get('id'))
			app.logger.info('Bulk acquisition action STOP DOWNLOAD - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			return redirect("/bulk", code=302)
	else:
		return redirect("/login", code=302)

				
### Reports
############

@app.route('/reports')
def reports():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		return render_template('ht_reports.html', session=session)
	else:
		return redirect("/login", code=302)

@app.route('/reportgen')
def reportgen():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		if request.args.get('id'):
			if request.args.get('id') == "1":
				reportFrom = request.args.get('startDate')
				reportTo = request.args.get('stopDate')
				alertsjson = restGetAlertsTime(session['ht_token'], reportFrom, reportTo, session['ht_ip'], session['ht_port'])
				
				if request.args.get('type') == "csv":
					reportdata = str(formatAlertsCsv(alertsjson, session['ht_token'], session['ht_ip'], session['ht_port']))
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
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):

			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()			
			
			if request.args.get('stop'):
				sqlChangeStackJobState(c, conn, request.args.get('stop'), session['ht_profileid'], "STOPPING")
				app.logger.info('Data stacking action STOP - User: ' + session['ht_user'] + "@" + session['ht_ip'])
				return redirect("/stacking", code=302)

			if request.args.get('remove'):
				sqlChangeStackJobState(c, conn, request.args.get('remove'), session['ht_profileid'], "REMOVING")
				app.logger.info('Data stacking action REMOVE - User: ' + session['ht_user'] + "@" + session['ht_ip'])
				return redirect("/stacking", code=302)

				
			if request.method == 'POST':
				out = sqlAddStackJob(c, conn, session['ht_profileid'], request.form['stacktype'], request.form['stackhostset'])
				app.logger.info('New data stacking job - User: ' + session['ht_user'] + "@" + session['ht_ip'])
			
			hs = restListHostsets(session['ht_token'], session['ht_ip'], session['ht_port'])
			hostsets = formatHostsets(hs)
			
			stacktable = formatStackTable(c, conn, session['ht_profileid'], hs)
			
			return render_template('ht_stacking.html', stacktable=stacktable, hostsets=hostsets)
	else:
			return redirect("/login", code=302)

@app.route('/stackinganalyze', methods=['GET', 'POST'])
def stackinganalyze():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
		
		conn = sqlite3.connect('hxtool.db')
		c = conn.cursor()
		
		stackid = request.args.get('id')
		
		stackdata = sqlGetServiceMD5StackData(c, conn, stackid)
		stacktable = formatServiceMD5StackData(stackdata)
		
		return render_template('ht_stacking_analyze_svcmd5.html', stacktable=stacktable)
	else:
		return redirect("/login", code=302)
		
			
### Settings
############
			
@app.route('/settings', methods=['GET', 'POST'])
def settings():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], session['ht_port']):
	
			conn = sqlite3.connect('hxtool.db')
			c = conn.cursor()
	
			if (request.method == 'POST'):
				out = sqlInsertProfCredsInfo(c, conn, session['ht_profileid'], request.form['bguser'], request.form['bgpass'])
				app.logger.info("Background Processing credentials set profileid: " + session['ht_profileid'] + " by user: " + session['ht_user'] + "@" + session['ht_ip'])
			
			if request.args.get('unsetprofcreds'):
				out = sqlDeleteProfCredsInfo(c, conn, session['ht_profileid'])
				app.logger.info("Background Processing credentials unset profileid: " + session['ht_profileid'] + " by user: " + session['ht_user'] + "@" + session['ht_ip'])
				return redirect("/settings", code=302)
			
			bgcreds = formatProfCredsInfo(c, conn, session['ht_profileid'])
			
			return render_template('ht_settings.html', bgcreds=bgcreds)
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
			(profileid, myip) = request.form['ht_ip'].split("__")
			hxport = '3000'
			if ':' in myip:
				hxip_port = myip.split(':')
				myip = hxip_port[0]
				if 0 < int(hxip_port[1]) <= 65535:
					hxport = hxip_port[1]
			
			(resp, message) = restValidateAuth(myip, hxport, request.form['ht_user'], request.form['ht_pass'])
			if resp:
				# Set session variables
				session['ht_user'] = request.form['ht_user']
				session['ht_ip'] = myip
				session['ht_port'] = hxport
				session['ht_token'] = message
				session['ht_profileid'] = profileid
				app.logger.info("Successful Authentication - User: {0}@{1}:{2}".format(session['ht_user'], session['ht_ip'], session['ht_port']))
				return redirect("/", code=302)
			else:
				options = ""
				for profile in sqlGetProfiles(c):
					options += "<option value='" + str(profile[0]) + "__" + profile[2] + "'>" + profile[1] + " - " + profile[2]
				return render_template('ht_login.html', fail=message, controllers=options)
			
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
	app.logger.info('User logged out: {0}@{1}:{2}'.format(session['ht_user'], session['ht_ip'], session['ht_port']))
	session.pop('ht_user', None)
	return redirect("/", code=302)


### Thread: background processing 
#################################
		
def bgprocess(myConf):
	
	time.sleep(1)
	app.logger.info('Background processor thread started')
	# SQLITE3
	conn = sqlite3.connect('hxtool.db')
	c = conn.cursor()
	
	while True:
		try:
			backgroundStackProcessor(c, conn, myConf, app)
		except BaseException as e:
			print('{!r}; StackProcessor error'.format(e))
		
		try:
			backgroundBulkProcessor(c, conn, myConf, app)
		except BaseException as e:
			print('{!r}; BulkProcessor error'.format(e))
			
		time.sleep(myConf['backgroundProcessor']['poll_interval'])
		
		
###########
### Main ####
###########			

app.secret_key = 'A0Zr98j/3yX23R~XH1212jmN]Llw/,?RT'
		
if __name__ == "__main__":

	# Logging
	handler = RotatingFileHandler('log/access.log', maxBytes=50000, backupCount=5)
	handler.setLevel(logging.INFO)
	
	ht_handler = RotatingFileHandler('log/hxtool.log', maxBytes=50000, backupCount=5)
	ht_handler.setLevel(logging.INFO)
	
	c_handler = logging.StreamHandler(sys.stdout)
	c_handler.setLevel(logging.INFO)
	
	# WSGI Server logging
	logger = logging.getLogger('werkzeug')
	logger.setLevel(logging.INFO)
	logger.addHandler(handler)
	
	# Flask logging
	app.logger.setLevel(logging.INFO)
	app.logger.addHandler(ht_handler)
	app.logger.addHandler(c_handler)
	
	# Set formatter
	formatter = logging.Formatter("[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s")
	handler.setFormatter(formatter)
	ht_handler.setFormatter(formatter)
	c_handler.setFormatter(formatter)

	# Start
	app.logger.info('Application starting')

	myConf = hxtool_config('conf.json', app.logger).get_config()

	# Start background processing thread
	thread = threading.Thread(target=bgprocess, name='BackgroundProcessor', args=(myConf,))
	thread.daemon = True
	thread.start()
	app.logger.info('Background Processor thread starting')
	
	if myConf['network']['ssl'] == "enabled":
		context = (myConf['ssl']['cert'], myConf['ssl']['key'])
		app.run(host=myConf['network']['listen_on'], port=myConf['network']['port'], ssl_context=context, threaded=True)
	else:
		app.run(host=myConf['network']['listen_on'], port=myConf['network']['port'])
