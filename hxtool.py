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

app = Flask(hxtool_global.root_logger_name, static_url_path='/static')

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
	return render_template('ht_main-dashboard.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### AV Dashboard
@app.route('/dashboard-av', methods=['GET'])
@valid_session_required
def dashboardav(hx_api_object):
	return render_template('ht_dashboard-av.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### New host drilldown page
@app.route('/hostview', methods=['GET'])
@valid_session_required
def host_view(hx_api_object):
	myscripts = app.hxtool_db.scriptList()
	scripts = formatScriptsFabric(myscripts)

	mytaskprofiles = app.hxtool_db.taskProfileList()
	taskprofiles = formatTaskprofilesFabric(mytaskprofiles)

	return render_template('ht_host_view.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), scripts=scripts, taskprofiles=taskprofiles)

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
	myauditspacefile = open(combine_app_path('static/acquisitions.json'), 'r')
	auditspace = myauditspacefile.read()
	myauditspacefile.close()
	return render_template('ht_scriptbuilder.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), auditspace=auditspace)

### Task profile page
@app.route('/taskprofile', methods=['GET', 'POST'])
@valid_session_required
def taskprofile(hx_api_object):
	return render_template('ht_taskprofile.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Bulk acq page
@app.route('/bulkacq', methods=['GET'])
@valid_session_required
def bulkacq_view(hx_api_object):
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsetsFabric(response_data)

	myscripts = app.hxtool_db.scriptList()
	scripts = formatScriptsFabric(myscripts)

	mytaskprofiles = app.hxtool_db.taskProfileList()
	taskprofiles = formatTaskprofilesFabric(mytaskprofiles)

	return render_template('ht_bulkacq.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostsets=hostsets, scripts=scripts, taskprofiles=taskprofiles)

### Hosts
@app.route('/hostsearch', methods=['GET', 'POST'])
@valid_session_required
def hosts(hx_api_object):
	return render_template('ht_hostsearch.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### Acquisitions listing
@app.route('/acqs', methods=['GET'])
@valid_session_required
def acqs(hx_api_object):
	return render_template('ht_acqs.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

#### Enterprise Search
@app.route('/search', methods=['GET'])
@valid_session_required
def search(hx_api_object):	
	(ret, response_code, response_data) = hx_api_object.restListHostsets()
	hostsets = formatHostsetsFabric(response_data)

	myiocs = app.hxtool_db.oiocList()
	openiocs = formatOpenIocsFabric(myiocs)
	
	return render_template('ht_searchsweep.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port), hostsets=hostsets, openiocs=openiocs)

@app.route('/searchresult', methods=['GET'])
@valid_session_required
def searchresult(hx_api_object):
	if request.args.get('id'):
		(ret, response_code, response_data) = hx_api_object.restGetSearchResults(request.args.get('id'))
		return render_template('ht_search_dd.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))
			
### Manage Indicators
###############################
### TODO: CONVERT TO API!!! ###
###############################
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
					app.logger.info(format_activity_log(msg="real-time indicator was deleted", name=request.args.get('delete'), category=request.args.get('category'), user=session['ht_user'], controller=session['hx_ip']))
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
					app.logger.info(format_activity_log(msg="new real-time indicator created", name=mydata['name'], category=mydata['category'], user=session['ht_user'], controller=session['hx_ip']))
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
					app.logger.info(format_activity_log(msg="real-time indicator was edited", name=mydata['name'], category=mydata['category'], user=session['ht_user'], controller=session['hx_ip']))
					return('', 204)
				else:
					# Failed to create indicator
					return('',500)
			else:
				# Invalid request
				return('', 500)

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
			#app.logger.info('Bulk acquisition download - User: %s@%s:%s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
			#app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('id'))
			app.logger.info(format_activity_log(msg="bulk acquisition download", id=request.args.get('id'), user=session['ht_user'], controller=session['hx_ip']))
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
			#app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('id'))
			print(response_data.headers)
			app.logger.info(format_activity_log(msg="acquisition download", id=request.args.get('id'), user=session['ht_user'], controller=session['hx_ip']))
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
				#app.logger.info('Acquisition download - User: %s@%s:%s - URL: %s', session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, request.args.get('acq_id'))
				app.logger.info(format_activity_log(msg="multi-file acquisition download", id=request.args.get('acq_id'), user=session['ht_user'], controller=session['hx_ip']))
				return send_file(path, attachment_filename=os.path.basename(path), as_attachment=True)
		else:
			return "HX controller responded with code {0}: {1}".format(response_code, response_data)
	abort(404)		

##### NEED TO IMPLEMENT THIS IN AN API CALL FOR BULK ACQ
#if request.args.get('action') == "stopdownload":
#ret = app.hxtool_db.bulkDownloadUpdate(request.args.get('id'), stopped = True)
#app.logger.info(format_activity_log(msg="bulk acquisition action", action="stop download", id=request.args.get('id'), user=session['ht_user'], controller=session['hx_ip']))
#return redirect("/bulkacq", code=302)

### Scripts
@app.route('/scripts', methods=['GET', 'POST'])
@valid_session_required
def scripts(hx_api_object):
	return render_template('ht_scripts.html', user=session['ht_user'], controller='{0}:{1}'.format(hx_api_object.hx_host, hx_api_object.hx_port))

### OpenIOCs
###############################
### TODO: CONVERT TO API!!! ###
###############################
@app.route('/openioc', methods=['GET', 'POST'])
@valid_session_required
def openioc(hx_api_object):
	if request.method == "POST":
		fc = request.files['ioc']				
		rawioc = fc.read()
		app.hxtool_db.oiocCreate(request.form['iocname'], HXAPI.b64(rawioc), session['ht_user'])
		app.logger.info(format_activity_log(msg="new openioc file stored", name=request.form['iocname'], user=session['ht_user'], controller=session['hx_ip']))
		return redirect("/openioc", code=302)
	elif request.method == "GET":
		if request.args.get('action'):
			if request.args.get('action') == "delete":
				app.hxtool_db.oiocDelete(request.args.get('id'))
				app.logger.info(format_activity_log(msg="openioc file deleted", id=request.args.get('id'), user=session['ht_user'], controller=session['hx_ip']))
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
				#app.logger.info('MultiFile Job ID {0} action STOP - User: {1}@{2}:{3}'.format(mf_job.eid, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
				app.logger.info(format_activity_log(msg="multif-file job", action="stop", id=mf_job.eid, user=session['ht_user'], controller=session['hx_ip']))

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
				#app.logger.info('MultiFile Job ID {0} action REMOVE - User: {1}@{2}:{3}'.format( mf_job.eid, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port))
				app.logger.info(format_activity_log(msg="multif-file job", action="delete", id=mf_job.eid, user=session['ht_user'], controller=session['hx_ip']))

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
						#app.logger.info('File acquisition requested from host %s at path %s- User: %s@%s:%s - host: %s', cf['hostname'], cf['FullPath'], session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, agent_id)
						app.logger.info(format_activity_log(msg="file acquistion requested", fromhost=cf['hostname'], path=cf['FullPath'], host=agent_id, user=session['ht_user'], controller=session['hx_ip']))
						file_jobs.append(acq_id)
						if len(file_jobs) >= MAX_FILE_ACQUISITIONS:
							break
					else:
						#TODO: Handle fail
						pass
			if file_jobs:
				#app.logger.info('New Multi-File Download requested (profile %s) - User: %s@%s:%s', profile_id, session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port)
				app.logger.info(format_activity_log(msg="new multi-file download", action="requested", user=session['ht_user'], controller=session['hx_ip']))
		
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
				#app.logger.info('File Listing ID {0} action STOP - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, file_listing_job.eid))
				app.logger.info(format_activity_log(msg="file listing action", action="stop", id=file_listing_job.eid, user=session['ht_user'], controller=session['hx_ip']))
		return redirect("/multifile", code=302)

	elif request.args.get('remove'):
		file_listing_job = app.hxtool_db.fileListingGetById(request.args.get('remove'))
		if file_listing_job:
			bulk_download_job = app.hxtool_db.bulkDownloadGet(file_listing_job['bulk_download_eid'])
			if bulk_download_job.get('bulk_acquisition_id', None):
				(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])
			app.hxtool_db.bulkDownloadDelete(file_listing_job['bulk_download_eid'])
			app.hxtool_db.fileListingDelete(file_listing_job.eid)
			#app.logger.info('File Listing ID {0} action REMOVE - User: {1}@{2}:{3}'.format(session['ht_user'], hx_api_object.hx_host, hx_api_object.hx_port, file_listing_job.eid))
			app.logger.info(format_activity_log(msg="file listing action", action="delete", id=file_listing_job.eid, user=session['ht_user'], controller=session['hx_ip']))
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
			bulk_download_eid = submit_bulk_job(hx_api_object, hostset, HXAPI.compat_str(script_xml), task_profile = "file_listing")
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
				app.logger.info(format_activity_log(msg="data stacking action", action="stop", user=session['ht_user'], controller=session['hx_ip']))
		return redirect("/stacking", code=302)

	if request.args.get('remove'):
		stack_job = app.hxtool_db.stackJobGet(request.args.get('remove'))
		if stack_job:
			bulk_download_job = app.hxtool_db.bulkDownloadGet(bulk_download_eid = stack_job['bulk_download_eid'])
			if bulk_download_job and 'bulk_acquisition_id' in bulk_download_job:
				(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', bulk_download_job['bulk_acquisition_id'])	
				app.hxtool_db.bulkDownloadDelete(bulk_download_job.eid)
				
			app.hxtool_db.stackJobDelete(stack_job.eid)
			app.logger.info(format_activity_log(msg="data stacking action", action="delete", user=session['ht_user'], controller=session['hx_ip']))
		return redirect("/stacking", code=302)

		
	if request.method == 'POST':
		stack_type = hxtool_data_models.stack_types.get(request.form['stack_type'])
		if stack_type:
			with open(combine_app_path('scripts', stack_type['script']), 'r') as f:
				script_xml = f.read()
				hostset_id = int(request.form['stackhostset'])
				bulk_download_eid = submit_bulk_job(hx_api_object, hostset_id, script_xml, task_profile = "stacking")
				ret = app.hxtool_db.stackJobCreate(session['ht_profileid'], bulk_download_eid, request.form['stack_type'])
				app.logger.info(format_activity_log(msg="new stacking job", hostset=request.form['stackhostset'], user=session['ht_user'], controller=session['hx_ip']))

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
		app.logger.info(format_activity_log(msg="background processing credentials action", action="set", profile=session['ht_profileid'], user=session['ht_user'], controller=session['hx_ip']))
		hxtool_global.task_hx_api_sessions[session['ht_profileid']] = HXAPI(hx_api_object.hx_host, 
																			hx_port = hx_api_object.hx_port, 
																			proxies = app.hxtool_config['network'].get('proxies'), 
																			headers = app.hxtool_config['headers'], 
																			cookies = app.hxtool_config['cookies'], 
																			logger_name = hxtool_global.get_submodule_logger_name(HXAPI.__name__), 
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
		app.logger.info(format_activity_log(msg="background processing credentials action", action="delete", user=session['ht_user'], controller=session['hx_ip']))
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
			app.logger.info(format_activity_log(msg="new configuration channel", profile=session['ht_profileid'], user=session['ht_user'], controller=session['hx_ip']))
		
		if request.args.get('delete'):
			(ret, response_code, response_data) = hx_api_object.restDeleteConfigChannel(request.args.get('delete'))
			app.logger.info(format_activity_log(msg="configuration channel action", action="delete", profile=session['ht_profileid'], user=session['ht_user'], controller=session['hx_ip']))
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

				hx_api_object = HXAPI(ht_profile['hx_host'], 
									hx_port = ht_profile['hx_port'], 
									proxies = app.hxtool_config['network'].get('proxies'), 
									headers = app.hxtool_config['headers'], 
									cookies = app.hxtool_config['cookies'], 
									logger_name = hxtool_global.get_submodule_logger_name(HXAPI.__name__), 
									default_encoding = default_encoding)

				(ret, response_code, response_data) = hx_api_object.restLogin(request.form['ht_user'], request.form['ht_pass'], auto_renew_token = True)
				if ret:
					# Set session variables
					session['ht_user'] = request.form['ht_user']
					session['ht_profileid'] = ht_profile['profile_id']
					session['ht_api_object'] = hx_api_object.serialize()
					session['hx_version'] = hx_api_object.hx_version
					session['hx_int_version'] = int(''.join(str(i) for i in hx_api_object.hx_version))
					session['hx_ip'] = hx_api_object.hx_host
					app.logger.info(format_activity_log(msg="user logged in", user=session['ht_user'], controller=session['hx_ip']))
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
			app.logger.info(format_activity_log(msg="user logged out", user=session['ht_user'], controller=session['hx_ip']))
			hx_api_object = None	
		session.clear()
	return redirect("/login", code=302)

		
###########
### Main ##
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
	exit(0)	


def app_init(debug = False):
	hxtool_global.initialize()
	
	hxtool_global.app_instance_path = app.root_path
	
	# Log early init/failures to stdout
	console_log = logging.StreamHandler(sys.stdout)
	console_log.setFormatter(logging.Formatter('[%(asctime)s] {%(module)s} {%(threadName)s} %(levelname)s - %(message)s'))
	app.logger.addHandler(console_log)
	
	db_write_cache_size = 10
	# If we're debugging use a static key
	if debug:
		app.secret_key = 'B%PT>65`)x<3_CRC3S~D6CynM7^F~:j0'.encode(default_encoding)
		app.logger.setLevel(logging.DEBUG)
		app.logger.debug("Running in debugging mode.")
		db_write_cache_size = 1
	else:
		app.secret_key = crypt_generate_random(32)
		app.logger.setLevel(logging.INFO)
	
	# Init DB
	app.hxtool_db = hxtool_db('hxtool.db', logger = app.logger, write_cache_size = db_write_cache_size)
	hxtool_global.hxtool_db = app.hxtool_db
	
	app.hxtool_config = hxtool_config(combine_app_path('conf.json'), logger = app.logger)
	hxtool_global.hxtool_config = app.hxtool_config
	
	app.task_api_key = 'Z\\U+z$B*?AiV^Fr~agyEXL@R[vSTJ%N&'.encode(default_encoding)
	
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
																					logger_name = hxtool_global.get_submodule_logger_name(HXAPI.__name__), 
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
	hxtool_global.hxtool_scheduler = hxtool_scheduler(logger = app.logger)
	hxtool_global.hxtool_scheduler.start()
	hxtool_global.hxtool_scheduler.load_from_database()
	
	
	# Initialize configured log handlers
	for log_handler in app.hxtool_config.log_handlers():
		app.logger.addHandler(log_handler)
	
	app.config['SESSION_COOKIE_NAME'] = "hxtool_session"
	app.permanent_session_lifetime = datetime.timedelta(days=7)
	app.session_interface = hxtool_session_interface(app, logger = app.logger, expiration_delta=app.hxtool_config['network']['session_timeout'])

	set_svg_mimetype()
	
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