
from hxtool_config import *
from hx_lib import *
from hxtool_db import *
import time

def formatListSearches(s):
	x = "<table id='searchTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>id</td>"
	x += "<td>input type</td>"
	x += "<td>created at</td>"
	x += "<td>host-set</td>"
	x += "<td>state</td>"
	x += "<td># hosts</td>"
	x += "<td># Complete</td>"
	x += "<td># Queued</td>"
	x += "<td># Failed</td>"
	x += "<td># Matched</td>"
	x += "<td># Not matched</td>"
	x += "<td style='width: 160px;'>Complete rate</td>"
	x += "<td style='width: 160px;'>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"

	for entry in s['data']['entries']:
		x += "<tr class='clickable-row' data-href='/searchresult?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + entry['input_type'] + "</td>"
		x += "<td>" + entry['create_time'] + "</td>"
		x += "<td>" + entry['host_set']['name'] + "</td>"
		x += "<td>" + entry['state'] + "</td>"
		x += "<td>" + str(entry['stats']['hosts']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + str(entry['stats']['search_state']['MATCHED']) + "</td>"
		x += "<td>" + str(entry['stats']['search_state']['NOT_MATCHED']) + "</td>"
		x += "<td>"
		if entry['stats']['hosts'] > 0:
			completerate = (float(entry['stats']['running_state']['COMPLETE']) / float(entry['stats']['hosts'])) * 100
		else:
			completerate = 0
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + str(entry['_id']) + "' data-percent='" + str(int(round(completerate))) + "'></div></div>"
		x += "</td>"
		x += "<td>" 
		x += "<a class='tableActionButton' href='/searchaction?action=stop&id=" + str(entry['_id']) + "'>stop</a>"
		x += "<a class='tableActionButton' href='/searchaction?action=remove&id=" + str(entry['_id']) + "'>remove</a>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)

def formatListSearchesJobDash(s):
	
	x = "<table id='searchTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>input type</td>"
	x += "<td>created at</td>"
	x += "<td>host-set</td>"
	x += "<td>state</td>"
	x += "<td>hosts</td>"
	x += "<td>complete</td>"
	
	
	x += "<td>matched</td>"
	x += "<td>nomatch</td>"
	x += "<td>actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"

	for entry in s['data']['entries']:
	
		if not (entry['state'] == "RUNNING"):
			continue
	
		x += "<tr>"
		
		x += "<td>" + entry['input_type'] + "</td>"
		x += "<td>" + entry['create_time'] + "</td>"
		x += "<td>" + entry['host_set']['name'] + "</td>"
		x += "<td>" + entry['state'] + "</td>"
		x += "<td>" + str(entry['stats']['hosts']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		
		
		x += "<td>" + str(entry['stats']['search_state']['MATCHED']) + "</td>"
		x += "<td>" + str(entry['stats']['search_state']['NOT_MATCHED']) + "</td>"
		x += "<td>" 
		x += "<a class='tableActionButton' href='/searchaction?action=stop&id=" + str(entry['_id']) + "'>stop</a>"
		x += "<a class='tableActionButton' href='/searchaction?action=remove&id=" + str(entry['_id']) + "'>remove</a>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)

def formatSearchResults(hostresults):

	x = "<table id='resultsTable' class='genericTable' style='width: 100%;'>" \
		"<thead>" \
		"<tr>" \
		"<td style='width: 100px;'>host</td>" \
		"<td style='width: 180px;'>type</td>" \
		"<td>data</td>" \
		"</tr>" \
		"</thead>" \
		"<tbody>"

	for entry in hostresults['data']['entries']:
		for result in entry['results']:
			x += "<tr>"
			if 'hostname' in entry['host']:
				x += "<td>" + entry['host']['hostname'] + "</td>"
			else:
				x += "<td>" + entry['host']['_id'] + "</td>"
			x += "<td>" + result['type'] + "</td>"
			x += "<td>"
			for data in result['data']:
				x += "<b>" + data + ":</b> " + str(result['data'][data]) + " "
			x += "</td>"
			x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatBulkTable(ht_db, bulktable, profileid):

	x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>" \
		"<thead>" \
		"<tr>" \
		"<td style='width: 100px;'>id</td>" \
		"<td style='width: 100px;'>state</td>" \
		"<td>Hostset ID</td>" \
		"<td>New</td>" \
		"<td>Queued</td>" \
		"<td>Failed</td>" \
		"<td>Complete</td>" \
		"<td>Aborted</td>" \
		"<td>Deleted</td>" \
		"<td>Refresh</td>" \
		"<td>Cancelled</td>" \
		"<td style='width: 160px;'>Complete rate</td>" \
		"<td style='width: 160px;'>Download rate</td>" \
		"<td style='width: 260px;'>Actions</td>" \
		"</tr>" \
		"</thead>" \
		"<tbody>"

	for entry in bulktable['data']['entries']:

	
		bulk_download = ht_db.bulkDownloadGet(profileid, entry['_id'])
		
		x += "<tr class='clickable-row' data-href='/bulkdetails?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		hostset_id = ""
		if entry['host_set']:
			hostset_id = entry['host_set']['_id']
		elif entry['comment'] and 'hostset_id' in entry['comment']:
			hostset_id = json.loads(entry['comment'])['hostset_id']
		x += "<td>{0}</td>".format(hostset_id)
		x += "<td>" + str(entry['stats']['running_state']['NEW']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['ABORTED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['DELETED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['REFRESH']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['CANCELLED']) + "</td>"
		x += "<td>"

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
		if total_size == 0:
			completerate = 0
		else:
			completerate = int(float(entry['stats']['running_state']['COMPLETE']) / float(total_size) * 100)
		
		if completerate > 100:
			completerate = 100
		
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + str(entry['_id']) + "' data-percent='" + str(int(round(completerate))) + "'></div></div>"
		x += "</td>"
		
		if bulk_download:
			total_hosts = len(bulk_download['hosts'])
			hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
			if total_hosts > 0 and hosts_completed > 0:
				
				dlprogress = int(float(hosts_completed) / total_hosts * 100)
							
				if dlprogress > 100:
					dlprogress = 100
					
			else:
				dlprogress = 0
			x += "<td>"
			x += "<div class='htMyBar htBarWrap'><div class='htBar' id='prog_" + str(entry['_id']) + "' data-percent='" + str(dlprogress) + "'></div></div>"
			x += "</td>"
		else:
			x += "<td>N/A</td>"
			
		x += "<td>" 
		
		if bulk_download and bulk_download['post_download_handler']:
			x += "Post-download handler: {0}".format(bulk_download['post_download_handler'])
		else:
			x += "<a class='tableActionButton' href='/bulkaction?action=stop&id=" + str(entry['_id']) + "'>stop</a>"
			x += "<a class='tableActionButton' href='/bulkaction?action=remove&id=" + str(entry['_id']) + "'>remove</a>"
			if not bulk_download:
				x += "<a class='tableActionButton' href='/bulkaction?action=download&id=" + str(entry['_id']) + "'>download</a>"
			else:
				x += "<a class='tableActionButton' href='/bulkaction?action=stopdownload&id=" + str(entry['_id']) + "'>stop download</a>"
		x += "</td>"
		
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)

# Renders the bulk table on the Jobs dashboard
def formatBulkTableJobDash(ht_db, bulktable, profileid):

	x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>" \
		"<thead>" \
		"<tr>" \
		"<td style='width: 100px;'>id</td>" \
		"<td style='width: 100px;'>state</td>" \
		"<td>host set</td>" \
		"<td>Queued</td>" \
		"<td>Complete</td>" \
		"<td>% Complete</td>" \
		"<td>Actions</td>" \
		"</tr>" \
		"</thead>" \
		"<tbody>"

	for entry in bulktable['data']['entries']:
	
		if not (entry['state'] == "RUNNING"):
			continue

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
		if total_size == 0:
			completerate = float(0.0)
		else:
			completerate = (entry['stats']['running_state']['COMPLETE'] / float(total_size)) * 100

		x += "<tr>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>" + str(entry['host_set']['name']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(completerate) + " %</td>"
		x += "<td>" 
		out = sqlGetStackJobsForBulkId(c, conn, profileid, entry['_id'])
		if (len(out) > 0):
			x += "Stacking job"
		else:
			x += "<a class='tableActionButton' href='/bulkaction?action=stop&id=" + str(entry['_id']) + "'>stop</a>"
			x += "<a class='tableActionButton' href='/bulkaction?action=remove&id=" + str(entry['_id']) + "'>remove</a>"
		x += "</td>"
		
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)
		
		
def formatBulkHostsTable(hoststable):

	x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>" \
		"<thead>" \
		"<tr>" \
		"<td style='width: 100px;'>hostname</td>" \
		"<td style='width: 100px;'>queued at</td>" \
		"<td style='width: 100px;'>completed at</td>" \
		"<td style='width: 100px;'>state</td>" \
		"<td>actions</td>" \
		"</tr>" \
		"</thead>" \
		"<tbody>" 


	for entry in hoststable['data']['entries']:
		x += "<tr>"
		x += "<td>" + str(entry['host']['hostname']) + "</td>"
		#x += "<td>" + str(entry['host']['_id']) + "</td>"
		x += "<td>" + str(entry['queued_at']) + "</td>"
		x += "<td>" + str(entry['complete_at']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>"
		if str(entry['state']) == "COMPLETE":
			x += "<a class='tableActionButton' href='/bulkdownload?id=" + str(entry['result']['url']) + "'>Download acquisition</a>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatIOCResults(iocs):

	x = "<table id='iocTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 40px;'>&nbsp;</td>"
	x += "<td>Name</td>"
	x += "<td style='width: 180px;'>Active since</td>"
	x += "<td style='width: 150px;'>Created by</td>"
	x += "<td style='width: 200px;'>Category</td>"
	x += "<td style='width: 80px;'>Platforms</td>"
	x += "<td style='width: 100px;'>Conditions</td>"
	x += "<td style='width: 120px;'>Hosts w/ alerts</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in iocs['data']['entries']:
		
		p = ""
		for platform in entry['platforms']:
			p += platform + ","
		p = p[:-1]
		
		x += "<tr class='clickable-row' data-value='" + str(entry['category']['uri_name']) + "___" + str(entry['uri_name']) + "'>"
		x += "<td><input type='checkbox' name='ioc___" + str(entry['display_name']) + "___" + str(entry['category']['uri_name']) + "___" + str(p) + "' value='" + str(entry['uri_name']) + "'></td>"
		x += "<td>" + str(entry['name']) + "</td>"
		x += "<td>" + str(entry['active_since']) + "</td>"
		x += "<td>" + str(entry['create_actor']['username']) + "</td>"
		x += "<td>" + str(entry['category']['name']) + "</td>"
		x += "<td>"
		for platform in entry['platforms']:
			x += str(platform) + "<br>"
		x += "</td>"
		x += "<td>" + str(entry['stats']['active_conditions']) + "</td>"
		x += "<td>" + str(entry['stats']['alerted_agents']) + "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatConditions(cond_pre, cond_ex):
	
	x = ""
	if len(cond_pre['data']['entries']) > 0:
		x += "<div class='tableTitle'>Presence conditions</div>"

		x += "<div style='margin-bottom: 10px; margin-top: -18px;' class='clt'>"
		x += "<ul>"
		x += "<li>or"
		x += "<ul>"
		for entry in cond_pre['data']['entries']:
			x += "<li>and"
			x += "<ul>"
			for test in entry['tests']:
				if 'negate' in test:
					x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
				else:
					x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
			x += "</ul>"
			x += "</li>"
		
		x += "</ul>"
		x += "</li>"
		x += "</div>"
	
	if len(cond_ex['data']['entries']) > 0:
		x += "<div class='tableTitle'>Execution conditions</div>"
		
		x += "<div style='margin-bottom: 10px; margin-top: -18px;' class='clt'>"
		x += "<ul>"
		x += "<li>or"
		x += "<ul>"
		for entry in cond_ex['data']['entries']:
			x += "<li>and"
			x += "<ul>"
			for test in entry['tests']:
				x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
			x += "</ul>"
			x += "</li>"
		
		x += "</ul>"
		x += "</li>"
		x += "</div>"
		
	return (x)
	
def formatCategoriesSelect(cats):

	x = "<select name='cats' id='cats'>"
	for entry in cats['data']['entries']:
		x += "<option value='" + entry['uri_name'] + "'>" + entry['name']
	x += "</select>"
	return(x)

def formatCategories(cats):

	x = "<table id='categoryTable' class='categoryTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 100px;'>Name</td>"
	x += "<td style='width: 100px;'>Retention policy</td>"
	x += "<td style='width: 100px;'>Edit policy</td>"
	x += "<td style='width: 100px;'>Source Alerts enabled</td>"
	x += "<td style='width: 100px;'>Signature enabled</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in cats['data']['entries']:
		x += "<tr>"
		x += "<td>" + str(entry['name']) + "</td>"
		x += "<td>" + str(entry['retention_policy']) + "</td>"
		x += "<td>" + str(entry['ui_edit_policy']) + "</td>"
		x += "<td>" + str(entry['ui_source_alerts_enabled']) + "</td>"
		x += "<td>" + str(entry['ui_signature_enabled']) + "</td>"
		x += "</tr>"
		
	x += "</tbody>"
	x += "</table>"
	
	return(x)
	
def formatHostsets(hs):
	
	x = ""
	
	for entry in hs['data']['entries']:
		x += "<option value='" + str(entry['_id']) + "'>" + entry['name']
	
	return(x)
	
def formatDashAlerts(alerts, hx_api_object):

	x = "<table id='dashAlerts' class='dashAlerts' style='width: 100%;'>" \
		"<thead>" \
		"<tr>" \
		"<td style='width: 100px;'>Host</td>" \
		"<td style='width: 100px;'>Domain</td>" \
		"<td style='width: 150px;'>Operating system</td>" \
		"<td style='width: 100px;'>Threat info</td>" \
		"<td style='width: 100px;'>Reported at</td>" \
		"<td style='width: 100px;'>Matched at</td>" \
		"</tr>" \
		"</thead>" \
		"<tbody>"

	for entry in alerts[:10]:
		x += "<tr>"
		(ret, response_code, response_data) = hx_api_object.restGetHostSummary(str(entry['agent']['_id']))
		x += "<td><a class='hostLink' href='/hosts?host=" + str(response_data['data']['_id']) + "&alertid=" + str(entry['_id']) + "'>" + str(response_data['data']['hostname']) + "</a></td>"
		x += "<td>" + str(response_data['data']['domain']) + "</td>"
		x += "<td>" + str(response_data['data']['os']['product_name']) + " " + str(response_data['data']['os']['patch_level']) + " " + str(response_data['data']['os']['bitness']) + "</td>"
		x += "<td>"
		if str(entry['source']) == "IOC":
			(ret, response_code, response_data) = hx_api_object.restGetIndicatorFromCondition(str(entry['condition']['_id']))
			for indicator in response_data['data']['entries']:
				x += "<b>Indicator:</b> " + indicator['name'] + " (" + indicator['category']['name'] + ")<br>"
		elif str(entry['source']) == "MAL":
			x += "<b>" + entry['event_values']['detections']['detection'][0]['infection']['infection-type'][0].upper() + entry['event_values']['detections']['detection'][0]['infection']['infection-type'][1:] + ": </b>" + entry['event_values']['detections']['detection'][0]['infection']['infection-name'] + " (" + entry['event_values']['detections']['detection'][0]['infection']['confidence-level'] + ")"
		elif str(entry['source']) == "EXD":
			x += "<b>Exploit:</b> " + str(len(entry['event_values']['messages'])) + " malicous behaviors"
		else:
			x += "Unknown alert"
		x += "</td>"
		x += "<td>" + str(entry['reported_at']) + "</td>"
		x += "<td>" + str(entry['matched_at']) + "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"

	return(x)

def formatAlertsTable(alerts, hx_api_object, profileid, ht_db):

	x = "<table id='alertsTable' class='genericTable genericTableAlerts' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 30px; text-align: center;'>OS</td>"
	x += "<td style='width: 100px;'>Host</td>"
	x += "<td style='width: 120px;'>Domain</td>"
	x += "<td style='width: 100px; text-align: center;'>Alerted</td>"
	x += "<td style='width: 150px;'>Reported at</td>"
	x += "<td style='width: 150px;'>Matched at</td>"
	x += "<td style='width: 100px; text-align: center;'>Containment</td>"
	x += "<td style='width: 60px; text-align: center;'>Threat</td>"
	x += "<td style=''>Threat name</td>"
	x += "<td style='width: 70px; text-align: center;'>State</td>"
	x += "<td style='width: 80px; text-align: center;'>Annotations</td>"
	x += "<td style='width: 100px;'>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"

	
	for entry in alerts['data']['entries']:
		
		# Get annotations
		alert = ht_db.alertGet(profileid, entry['_id'])
		annotation_count = 0
		annotation_max_state = 0
		if alert:
			annotation_count = len(alert['annotations'])
			annotation_max_state = int(max(alert['annotations'], key = (lambda k: k['state']))['state'])
		
		bgcolor = "#ffffff"
		if (annotation_max_state == 1):
			bgcolor = "#fffce0"
		elif (annotation_max_state == 2):
			bgcolor = "#e0ffe3"		
	
		x += "<tr>"
	
		(ret, response_code, response_data) = hx_api_object.restGetHostSummary(str(entry['agent']['_id']))
		
		# OS
		x += "<td><center>"
		if str(response_data['data']['os']['product_name']).startswith('Windows'):
			x += "<img style='width: 20px;' src='/static/ico/windows.svg'>"
		else:
			x += "<img style='width: 20px;' src='/static/ico/apple.svg'>"
		x += "</center></td>"
		
		# Host
		x += "<td><a class='hostLink' href='/hosts?host=" + str(response_data['data']['_id']) + "&alertid=" + str(entry['_id']) + "'>" + str(response_data['data']['hostname']) + "</a></td>"
		
		# Domain
		x += "<td>" + str(response_data['data']['domain']) + "</td>"
		
		# Alerted
		import datetime
		t = HXAPI.gt(entry['reported_at'])
		x += "<td style='text-align: center; font-weight: 700;'>" + HXAPI.prettyTime(t) + "</td>"

		# Reported at
		x += "<td>" + str(entry['reported_at']) + "</td>"
		
		# Matched at
		x += "<td>" + str(entry['matched_at']) + "</td>"
		
		# Containment state
		x += "<td style='text-align: center;'>"
		x += str(entry['agent']['containment_state'])
		x += "</td>"
		
		# Event type
		x += "<td style='text-align: center;'>"
		if str(entry['source']) == "EXD":
			x += "<div class='tableActionIcon'>EXD</div>"
		elif (str(entry['source']) == "MAL"):
			x += "<div class='tableActionIcon'>MAL</div>"
		elif (str(entry['source']) == "IOC"):
			x += "<div class='tableActionIcon'>IOC</div>"
		else:
			x +="N/A"
		x += "</td>"
		
		# Event name
		x += "<td>"
		
		if str(entry['source']) == "EXD":
			x += str(entry['event_values']['process_name']) + " (pid: " + str(entry['event_values']['process_id']) + ") (count: " + str(len(entry['event_values']['messages'])) + ")"
			x += "<a class='tableActionButton' style='float: right; position: relative; right: 0; color: #ffffff; padding-left: 5px; padding-right: 5px;' href='/hosts?host=" + str(entry['agent']['_id']) + "&alertid=" + str(entry['_id']) + "'>Details</a>"
			
		elif (str(entry['source']) == "MAL"):
			x += entry['event_values']['detections']['detection'][0]['infection']['infection-name'] + " (severity: " + entry['event_values']['detections']['detection'][0]['infection']['confidence-level'] + ")"
			x += "<a class='tableActionButton' style='float: right; position: relative; right: 0; color: #ffffff; padding-left: 5px; padding-right: 5px;' href='/hosts?host=" + str(entry['agent']['_id']) + "&alertid=" + str(entry['_id']) + "'>Details</a>"
			
		elif (str(entry['source']) == "IOC"):
			(ret, response_code, response_data) = hx_api_object.restGetIndicatorFromCondition(str(entry['condition']['_id']))
			for indicator in response_data['data']['entries']:
				x += indicator['name'] + " (category: " + indicator['category']['name'] + ")"
						
			x += "<a class='tableActionButton' style='float: right; position: relative; right: 0; color: #ffffff; padding-left: 5px; padding-right: 5px;' href='/hosts?host=" + str(entry['agent']['_id']) + "&alertid=" + str(entry['_id']) + "'>Details</a>"
			
		else:
			x += "Unknown alert"
		
		x += "<a target='_blank' class='tableActionButton' style='float: right; position: relative; right: 0; color: #ffffff; padding-left: 5px; padding-right: 5px;' href='https://" + hx_api_object.hx_host + ":" + str(hx_api_object.hx_port) + "/hx/hosts/" + entry['agent']['_id'] + "/alerts/" + str(entry['_id']) + "'>HX</a>"
		x += "</td>"
		
		# State
		if (annotation_max_state == 1):
			x += "<td style='text-align: center; background: " + bgcolor + ";'>Investigating</td>"
		elif (annotation_max_state == 2):
			x += "<td style='text-align: center; background: " + bgcolor + ";'>Completed</td>"
		else:
			x += "<td style='text-align: center; background: " + bgcolor + ";'>New</td>"
			
		# Annotation status
		x += "<td style='text-align: center;'>"
			
		x += "<a href='#' id='adisp_" + str(entry['_id']) + "' class='tableActionButton'>show (" + str(annotation_count) + ")</a>"
		x += "</td>"
		
		# Actions
		x += "<td>"
		x += "<input class='tableActionButton' id='annotate_" + str(entry['_id']) + "' type='button' value='Annotate'>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return(x)

def formatAnnotationTable(an):

	x = "<table id='annotateDisplayTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 15%;'>Timestamp</td>"
	x += "<td style='width: 15%;'>User</td>"
	x += "<td style='width: 55%;'>Comment</td>"
	x += "<td style='width: 15%;'>Status</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"


	if an:
		for item in an:
		
			atext = "<br />".join(item['annotation'].split("\n"))
		
			x += "<tr>"
			x += "<td>" + str(item['create_timestamp']) + "</td>"
			x += "<td>" + str(item['create_user']) + "</td>"
			x += "<td>" + atext + "</td>"
			x += "<td>"
			
			if item['state'] == 1:
				x += "Investigating"
			elif item['state'] == 2:
				x += "Completed"
			else:
				x += "Unknown"
				
			x += "</td>"
			x += "</tr>"
		
	x += "</tbody>"
	x += "</table>"
		
	return (x)

def formatAlertsCsv(alertsjson, hx_api_object):

	x = "reported_at;matched_at;event_at;hostname;domain;source;productname;event_type;event_id\r\n"
	
	for entry in alertsjson:
		(ret, response_code, response_data) = hx_api_object.restGetHostSummary(str(entry['agent']['_id']))
		x += entry['reported_at'] + ";"
		x += entry['matched_at'] + ";"
		x += entry['event_at'] + ";"
		x += response_data['data']['hostname'] + ";"
		x += response_data['data']['domain'] + ";"
		x += str(entry['source']) + ";"
		x += response_data['data']['os']['product_name'] + " " + response_data['data']['os']['patch_level'] + " " + response_data['data']['os']['bitness'] + ";"
		x += str(entry['event_type']) + ";"
		x += str(entry['event_id'])
		x += "\r\n"

	return (x)
	

def formatProfCredsInfo(has_creds):

	x = ""
	
	if has_creds:
		x += "Background processing credentials are set <a href='/settings?unset=1'>Unset</a>"
	else:
		x += "<form method='POST'>"
		x += "<div>Username</div>"
		x += "<input name='bguser' type='text'>"
		x += "<div>Password</div>"
		x += "<input name='bgpass' type='password'>"
		x += "<br><input style='margin-top: 15px;' class='tableActionButton' type='submit' value='set'>"
		x += "</form>"
	
	return(x)

def formatCustomConfigChannels(ch):

	x = ""

	x += "<table id='channeltable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>Name</td>"
	x += "<td>Description</td>"
	x += "<td>Created</td>"
	x += "<td>Created by</td>"
	x += "<td>Priority</td>"
	x += "<td>Host sets</td>"
	x += "<td>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	for entry in ch['data']['entries']:
		x += "<tr class='clickable-row' data-href='/channelinfo?id=" + str(entry['_id']) + "'>"
		x += "<td>" + entry['name'] + "</td>"
		x += "<td>" + entry['description'] + "</td>"
		x += "<td>" + entry['create_time'] + "<//td>"
		x += "<td>" + entry['create_actor']['username'] + "</td>"
		x += "<td>" + str(entry['priority']) + "</td>"
		x += "<td>"
		for hset in entry['host_sets']:
			x += hset['name'] + "<br>"
		x += "</td>"
		x += "<td>"
		x += "<a href='/channels?delete=" +  str(entry['_id']) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		x += "</td>"
		x += "</tr>"
		
	x += "</tbody>"
	x += "</table>"
	return(x)
	
def formatStackTable(ht_db, profile_id, hs):

	x = ""
	
	stack_jobs = ht_db.stackJobList(profile_id)
	
	x += "<table id='stacktable' class='genericTable dataTable no-footer' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>ID</td>"
	x += "<td>Created</td>"
	x += "<td>Last updated</td>"
	x += "<td>Stack Type</td>"
	x += "<td>State</td>"
	x += "<td>Profile ID</td>"
	x += "<td>HX Bulk ID</td>"
	x += "<td>Hostset ID</td>"
	x += "<td style='width: 160px;'>Completion rate</td>"
	x += "<td style='width: 260px;'>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for job in stack_jobs:
		bulk_download = ht_db.bulkDownloadGet(job['profile_id'], job['bulk_download_id'])
		x += "<tr>"
		x += "<td>" + str(job.eid) + "</td>"
		x += "<td>" + str(job['create_timestamp']) + "</td>"
		x += "<td>" + str(job['update_timestamp']) + "</td>"
		x += "<td>" + job['stack_type'] + "</td>"
		x += "<td>" + ("STOPPED" if job['stopped'] else "RUNNING") + "</td>"
		x += "<td>" + str(job['profile_id'])	+ "</td>"
		x += "<td>" + str(job['bulk_download_id']) + "</td>"		
		x += "<td>" + str(bulk_download['hostset_id']) + "</td>"
		
		# Completion rate
		job_progress = 0
		hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
		job_progress = int(hosts_completed / float(len(bulk_download['hosts'])) * 100)
		x += "<td>"
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + str(job.eid) + "' data-percent='" + str(job_progress) + "'></div></div>"
		x += "</td>"
		
		# Actions
		x += "<td>"
		x += "<a href='/stacking?stop=" +  str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>stop</a>"
		x += "<a href='/stacking?remove=" +  str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		x += "<a href='/stackinganalyze?id=" +  str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>analyze</a>"
		x += "</td>"
		x += "</tr>"
	
	x += "</tbody>"
	x += "</table>"

	return(x)

	
# This is the alert investigation viewer
def formatHostInfo(response_data, hx_api_object):

	x = ""

	x += "<table id='hostinfo' class='genericTable' style='width: 100%; border-bottom: 0;'>"
	x += "<tbody>"
	x += "<tr>"

	# First box
	x += "<td style='width: 550px; border-right: 0;'>"
	
	if str(response_data['data']['os']['product_name']).startswith('Windows'):
		x += "<img style='float: left; width: 100px;' src='/static/ico/windows.svg'>"
	else:
		x += "<img style='float: left; width: 100px;' src='/static/ico/apple.svg'>"
		
	x += "<div style='float: left; padding-left: 10px;'>" 
	x += "<b>Hostname:</b> " + str(response_data['data']['hostname'])  + "<br>" 
	x += "<b>Domain:</b> " + str(response_data['data']['domain']) + "<br>"
	x += "<b>Last poll IP:</b> " + str(response_data['data']['last_poll_ip']) + "<br>"
	x += "<b>Last poll Timestamp:</b> " + str(response_data['data']['last_poll_timestamp']) + "<br>"
	x += "<b>Timezone:</b> " + str(response_data['data']['timezone']) + "<br>"
	x += "<b>Operating system:</b> " + str(response_data['data']['os']['product_name']) + " " + str(response_data['data']['os']['patch_level']) + " " + str(response_data['data']['os']['bitness']) + "<br>"
	
	(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(str(response_data['data']['_id']))
	if sret:
		x += "<b>Logged on user:</b> " + str(sresponse_data['data']['loggedOnUser']) + "<br>"
	x += "</div>"
	
	
	x += "</td>"
	
	# Second box
	x += "<td>"
	x += "<table style='width: 100%;'>"
	x += "<tr>"
	x += "<td style='width: 17%; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['alerting_conditions']) + "</span><br>Alerting conditions</td>"
	x += "<td style='width: 17%; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['exploit_alerts']) + "</span><br>Exploit alerts</td>"
	x += "<td style='width: 17%; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['acqs']) + "</span><br>Acquisitions</td>"
	x += "<td style='width: 17%; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['alerts']) + "</span><br>Alerts</td>"
	x += "<td style='width: 17%; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['exploit_blocks']) + "</span><br>Exploit blocks</td>"
	x += "<td style='width: 17%; text-align: center;'><span style='font-size: 32px; font-weight: bold;'>" + str(response_data['data']['stats']['malware_alerts']) + "</span><br>Malware alerts</td>"
	x += "</tr>"
	x += "</table>"
	x += "</td>"
	x += "</tr>"
	
	# Alerts view
	x += "<tr>"
	x += "<td style='width: 500px; padding: 0; vertical-align: top; border-right: 0; border-bottom: 1px solid #dddddd;'>"
	
	# Sub alert table start
	x += "<table id='hostAlertTable' class='genericTable genericTableSmall' style='width: 100%; border-right: 1px solid #dddddd; border-left: 1px solid #dddddd; margin-top: 15px; box-shadow: 8px 8px 5px rgb(215,215,215); margin-bottom: 20px;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='font-weight: bold; text-align: center;'>type</td>"
	x += "<td style='font-weight: bold; '>name</td>"
	x += "<td style='font-weight: bold; text-align: center;'>time</td>"
	x += "<td style='font-weight: bold; text-align: center;'>action</td>"
	x += "</tr>"
	x += "</thead>"

	(aret, aresponse_code, aresponse_data) = hx_api_object.restGetAlertsHost(response_data['data']['_id'])
	if aret:
		for alert in aresponse_data[0:15]:
			x += "<tr class='clickable-row' id='alert_" + str(alert['_id']) + "'>"
					
			x += "<td style='text-align: center; width: 40px;'>"
			if str(alert['source']) == "EXD":
				x += "<div class='tableActionIcon'>EXD</div>"
			elif (str(alert['source']) == "MAL"):
				x += "<div class='tableActionIcon'>MAL</div>"
			elif (str(alert['source']) == "IOC"):
				x += "<div class='tableActionIcon'>IOC</div>"
			else:
				x +="N/A"
			x += "</td>"
						
			x += "<td>"
			
			# IOC
			if str(alert['source']) == "IOC":
				(iret, iresponse_code, iresponse_data) = hx_api_object.restGetIndicatorFromCondition(str(alert['condition']['_id']))
				if iret:
					for indicator in iresponse_data['data']['entries']:
						x += indicator['name']
					
					# Alert details hidden div
					x += "<div style='display: none;' id='alertdetails_" + str(alert['_id']) + "'>"
					
					(cret, cresponse_code, cresponse_data) = hx_api_object.restGetConditionDetails(str(alert['condition']['_id']))
					if cret:
						x += "<div class='tableTitle'>Matching condition</div>"
		
						x += "<div style='margin-bottom: 20px; margin-top: -18px;' class='clt'>"
						x += "<ul>"
						x += "<li>or"
						x += "<ul>"
						x += "<li>and"
						x += "<ul>"
						for test in cresponse_data['data']['tests']:
							if 'negate' in test:
								x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
							else:
								x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
						x += "</ul>"
						x += "</li>"
		
						x += "</ul>"
						x += "</li>"
						x += "</div>"
		
					
					x += "<div class='tableTitle'>Indicator type: " + str(alert['event_type']) + "</div>"
					x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
					for hitkey, hitdata in alert['event_values'].iteritems():
						x += "<tr><td style='width: 300px;'>" + str(hitkey) + "</td><td>" + str(hitdata) + "</td></tr>"
					x += "</table>"
					x += "</div>"
			
			# EXG
			elif str(alert['source']) == "EXD":
				x += str(alert['event_values']['process_name']) + " (pid: " + str(alert['event_values']['process_id']) + ")"
			
				# Alert details hidden div
				x += "<div style='display: none;' id='alertdetails_" + str(alert['_id']) + "'>"
				x += "<div class='tableTitle'>Observed behavior</div>"
				x += "<ul>"
				for behavior in alert['event_values']['messages']:
					x += "<li>" + behavior
				x += "</ul>"
				x += "<br><br>"
				x += "<div class='tableTitle'>Initial exploited process</div>"
				x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 20px;'>"
				x += "<tr><td style='width: 150px;'>Initial exploit timestamp</td><td>" + alert['event_values']['earliest_detection_time'] + "</td></tr>"
				x += "<tr><td style='width: 150px;'>Process path</td><td>" + alert['event_values']['process_name'] + "</td></tr>"
				x += "<tr><td style='width: 150px;'>Process ID</td><td>" + alert['event_values']['process_id'] + "</td></tr>"
				x += "</table>"
				
				x += "<div class='tableTitle'>Analysis details</div>"
				x += "<table class='genericTable genericTableSmall' style='width: 100%;'>"
				x += "<tr>"
				x += "<td style='width: 150px; font-weight: bold;'>Type</td>"
				x += "<td style='width: 150px; font-weight: bold;'>Timestamp</td>"
				x += "<td style='font-weight: bold;'>Info</td>"
				x += "</tr>"
				
				skiplist = ['timestamp', 'analysis-id', 'eventid']
				for data in alert['event_values']['analysis_details']:
					if set(("detail_type", "detail_time")) <= set(data.keys()):
						x += "<tr>"
						x += "<td>" + data['detail_type'] + "</td>"
						x += "<td>" + data['detail_time'] + "</td>"
						x += "<td>"
						x += "<table class='genericTable genericTableSmall' style='width: 100%; border-top: 0; border-bottom: 0;'>"
						for itemkey, itemdata in data[data['detail_type']].iteritems():
							
							if itemdata != "N/A" and itemkey not in skiplist:
								x += "<tr>"
								if type(itemdata) is dict:
									x += "<td colspan='2'>"
									x += "<div class='clt'>"
									x += str(itemkey)
									x += "<ul style='margin-top: 0;'>"
									for dictkey, dictdetail in itemdata.iteritems():
										x += "<li>" + str(dictkey) + ": " + str(dictdetail) + "</li>"
									x += "</ul>"
									x += "</div>"
									x += "</td>"
								else:
									x += "<td style='width: 100px;'>" + str(itemkey) + "</td>"
									x += "<td>" + str(itemdata) + "</td>"
								
								x += "</tr>"
						x += "</table>"
						
							
						x += "</td>"
						x += "</tr>"
				x += "</table>"
				
					
				x += "</div>"
			
			# MAL
			elif str(alert['source']) == "MAL":
				x += alert['event_values']['detections']['detection'][0]['infection']['infection-name']
			
				# Alert details hidden div
				x += "<div style='display: none;' id='alertdetails_" + str(alert['_id']) + "'>"
				x += "<div class='tableTitle'>Malware alert: " + alert['event_values']['detections']['detection'][0]['infection']['infection-type'] + "</div>"
				x += "<table class='genericTable genericTableSmall' style='width: 100%;'>"
				for hitkey, hitdata in alert['event_values']['detections']['detection'][0]['infection'].iteritems():
					x += "<tr><td>" + str(hitkey) + "</td><td>" + str(hitdata) + "</td></tr>"
				for hitkey, hitdata in alert['event_values']['detections']['detection'][0]['infected-object']['file-object'].iteritems():
					x += "<tr><td>" + str(hitkey) + "</td><td>" + str(hitdata) + "</td></tr>"
				x += "</table>"
				x += "</div>"

			
			# UNKNOWN (new alert type?)
			else:
				x += "Unknown alert"
			
			x += "</td>"
			
			
			x += "<td style='text-align: center; width: 90px;'>"
			import datetime
			t = HXAPI.gt(alert['reported_at'])
			x += HXAPI.prettyTime(t)
			x += "</td>"
			
	
			x += "<td style='text-align: center; width: 60px;'>"
			x += str(alert['resolution'])
			x += "</td>"
			
			x += "</tr>"
			
	x += "</table>"
	# Sub alert table stop
	
	x += "</td>"
	x += "<td style='vertical-align: top; padding-top: 15px;'>"
	x += "<div id='alertcontent' style='margin-left: 10px; margin-bottom: 15px; padding: 15px; border: 1px solid #dddddd; box-shadow: 8px 8px 5px rgb(215,215,215);'></div>"
	x += "</td>"
	x += "</tr>"
	
	# Alerts context view
	
	# Acquisitions
	
	x += "<tr>"
	x += "<td colspan='2'>"

	(atret, atresponse_code, atresponse_data) = hx_api_object.restListTriageAcquisitionsHost(response_data['data']['_id'])
	
	if (atret):
		if (len(atresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>Triage acquisitions</div>"
			x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
			x += "<thead>"
			x += "<tr>"
			x += "<td style='font-weight: bold;'>Acquisition</td>"
			x += "<td style='font-weight: bold;'>Requested by</td>"
			x += "<td style='font-weight: bold;'>Requested</td>"
			x += "<td style='font-weight: bold;'>Status</td>"
			x += "<td style='width: 100px; font-weight: bold;'>Action</td>"
			x += "</tr>"
			for triage in atresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>"
				if triage['request_actor']['username'] == "automatic":
					x += "Automatic triage"
				else:
					x += "Normal triage"
				x += "</td>"
				x += "<td>" + str(triage['request_actor']['username']) + "</td>"
				x += "<td>" + str(triage['request_time']) + "</td>"
				x += "<td>" + str(triage['state']) + "</td>"
				x += "<td><a href='/download?id=" + str(triage['url']) + ".mans' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</table>"

	(afret, afresponse_code, afresponse_data) = hx_api_object.restListFileAcquisitionsHost(response_data['data']['_id'])
	if (afret):
		if (len(afresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>File acquisitions</div>"
			x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
			x += "<thead>"
			x += "<tr>"
			x += "<td style='font-weight: bold;'>Path</td>"
			x += "<td style='font-weight: bold;'>Filename</td>"
			x += "<td style='font-weight: bold;'>Requested by</td>"
			x += "<td style='font-weight: bold;'>Requested</td>"
			x += "<td style='font-weight: bold;'>Passphrase</td>"
			x += "<td style='font-weight: bold;'>Status</td>"
			x += "<td style='font-weight: bold;'>Error message</td>"
			x += "<td style='width: 100px; font-weight: bold;'>Action</td>"
			x += "</tr>"
			for fileaq in afresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>" + str(fileaq['req_path']) + "</td>"
				x += "<td>" + str(fileaq['req_filename']) + "</td>"
				x += "<td>" + str(fileaq['request_actor']['username']) + "</td>"
				x += "<td>" + str(fileaq['request_time']) + "</td>"
				x += "<td>" + str(fileaq['zip_passphrase']) + "</td>"
				x += "<td>" + str(fileaq['state']) + "</td>"
				x += "<td>" + str(fileaq['error_message']) + "</td>"
				x += "<td><a href='/download?id=" + str(fileaq['url']) + ".zip' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</table>"
		
	(adret, adresponse_code, adresponse_data) = hx_api_object.restListDataAcquisitionsHost(response_data['data']['_id'])
	if (adret):
		if (len(adresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>Data acquisitions</div>"
			x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
			x += "<thead>"
			x += "<tr>"
			x += "<td style='font-weight: bold;'>Name</td>"
			x += "<td style='font-weight: bold;'>Requested by</td>"
			x += "<td style='font-weight: bold;'>Requested</td>"
			x += "<td style='font-weight: bold;'>Status</td>"			
			x += "<td style='width: 100px; font-weight: bold;'>Action</td>"
			x += "</tr>"
			for daq in adresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>" + str(daq['name']) + "</td>"
				x += "<td>" + str(daq['request_actor']['username']) + "</td>"
				x += "<td>" + str(daq['request_time']) + "</td>"
				x += "<td>" + str(daq['state']) + "</td>"
				x += "<td><a href='/download?id=" + str(daq['url']) + ".mans' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</table>"

			
	x += "</td>"
	x += "</tr>"

	
	x += "</table>"
	
	return(x)
	
def formatHostSearch(response_data, hx_api_object):

	x = ""
	
	x += "<table id='hostinfo' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='font-weight: bold;'>Hostname</td>"
	x += "<td style='font-weight: bold;'>Domain</td>"
	x += "<td style='font-weight: bold;'>Primary IP</td>"
	x += "<td style='font-weight: bold;'>Last poll IP</td>"
	x += "<td style='font-weight: bold;'>Last poll timestamp</td>"
	x += "<td style='font-weight: bold;'>Containment</td>"
	x += "<td style='font-weight: bold;'>Initial provision</td>"
	x += "<td style='font-weight: bold;'>Operating system</td>"
	x += "<td style='font-weight: bold;'>Agent version</td>"
	x += "<td style='font-weight: bold;'>Action</td>"
	x += "</tr>"
	x += "</thead>"
	
	for host in response_data['data']['entries']:
		
		x += "<tr>"
		x += "<td><a class='hostLink' href='/hosts?host=" + str(host['_id']) + "'>" + str(host['hostname']) + "</a></td>"
		x += "<td>" + str(host['domain']) + "</td>"
		x += "<td>" + str(host['primary_ip_address']) + "</td>"
		x += "<td>" + str(host['last_poll_ip']) + "</td>"
		x += "<td>" + str(host['last_poll_timestamp']) + "</td>"
		
		x += "<td>"
		if (host['containment_state'] == "normal") and (host['containment_queued'] == True):
			x += "requested"
		else:
			x += str(host['containment_state'])
		x += "<div style='float: right;'>"
		if host['containment_state'] == "contained":
			x += "<a class='tableActionButton' id='uncontain_" + str(host['_id']) + "'>uncontain</a>"
		elif (host['containment_state'] == "normal") and (host['containment_queued'] == False):
			x += "<a class='tableActionButton' id='contain_" + str(host['_id']) + "'>contain</a>"
		elif (host['containment_state'] == "normal") and (host['containment_queued'] == True):
			x += "<a class='tableActionButton' id='appcontain_" + str(host['_id']) + "'>approve</a>"
		x += "</div>"
		x += "</td>"
		
		import datetime
		t = HXAPI.gt(host['initial_agent_checkin'])
		x += "<td>" + HXAPI.prettyTime(t) + "</td>"
				
		x += "<td>" + str(host['os']['product_name']) + " " + str(host['os']['patch_level']) + " " + str(host['os']['bitness']) + "</td>"
		x += "<td>" + str(host['agent_version']) + "</td>"
		
		x += "<td>"
		x += "<a class='tableActionButton' id='triage_" + str(host['_id']) + "'>triage</a>"
		x += "<a class='tableActionButton' id='fileaq_" + str(host['_id']) + "'>file acq</a>"
		x += "<a class='tableActionButton' id='acq_" + str(host['_id']) + "'>acquisition</a>"
		x += "</td>"
		
		x += "</tr>"
	
	x += "</table>"
	
	return (x)