
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

	x = "<table id='resultsTable' class='genericTable' style='width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>host</td>"
	x += "<td style='width: 180px;'>type</td>"
	x += "<td>data</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

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


def formatBulkTable(c, conn, bulktable, profileid):

        x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>id</td>"
        x += "<td style='width: 100px;'>state</td>"
        x += "<td>host set</td>"
        x += "<td>New</td>"
        x += "<td>Queued</td>"
        x += "<td>Failed</td>"
        x += "<td>Complete</td>"
        x += "<td>Aborted</td>"
        x += "<td>Deleted</td>"
        x += "<td>Refresh</td>"
        x += "<td>Cancelled</td>"
        x += "<td style='width: 160px;'>Complete rate</td>"
        x += "<td style='width: 160px;'>Download rate</td>"
        x += "<td style='width: 260px;'>Actions</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in bulktable['data']['entries']:


		out = sqlGetStackJobsForBulkId(c, conn, profileid, entry['_id'])
		bulkdl = sqlGetBulkDownloadStatus(c, conn, profileid, entry['_id'])
		print(entry)
		x += "<tr class='clickable-row' data-href='/bulkdetails?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>" + '' + "</td>"
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
		
		if (len(bulkdl) > 0):
			if (bulkdl[0][3] != 0 or bulkdl[0][2] != 0):
				
				dlprogress = float(bulkdl[0][3]) / float(bulkdl[0][2]) * 100
							
				if dlprogress > 100:
					dlprogress = 100
					
			else:
				dlprogress = 0
			x += "<td>"
			x += "<div class='htMyBar htBarWrap'><div class='htBar' id='prog_" + str(entry['_id']) + "' data-percent='" + str(int(round(dlprogress))) + "'></div></div>"
			x += "</td>"
		else:
			x += "<td>N/A</td>"
			
		x += "<td>" 
		
		if (len(out) > 0):
			x += "Stacking job"
		else:
			x += "<a class='tableActionButton' href='/bulkaction?action=stop&id=" + str(entry['_id']) + "'>stop</a>"
			x += "<a class='tableActionButton' href='/bulkaction?action=remove&id=" + str(entry['_id']) + "'>remove</a>"
			bulkdl = sqlGetBulkDownloadStatus(c, conn, profileid, str(entry['_id']))
			if (len(bulkdl) == 0):
				x += "<a class='tableActionButton' href='/bulkaction?action=download&id=" + str(entry['_id']) + "'>download</a>"
			else:
				x += "<a class='tableActionButton' href='/bulkaction?action=stopdownload&id=" + str(entry['_id']) + "'>stop download</a>"
		x += "</td>"
		
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"
        return (x)

# Renders the bulk table on the Jobs dashboard
def formatBulkTableJobDash(c, conn, bulktable, profileid):

        x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>id</td>"
        x += "<td style='width: 100px;'>state</td>"
        x += "<td>host set</td>"
        x += "<td>Queued</td>"
        x += "<td>Complete</td>"
        x += "<td>% Complete</td>"
        x += "<td>Actions</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

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

        x = "<table id='bulkTable' class='genericTable' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>hostname</td>"
        x += "<td style='width: 100px;'>queued at</td>"
        x += "<td style='width: 100px;'>completed at</td>"
        x += "<td style='width: 100px;'>state</td>"
        x += "<td>actions</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"


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

	x = "<table id='dashAlerts' class='dashAlerts' style='width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>Host</td>"
        x += "<td style='width: 100px;'>Domain</td>"
        x += "<td style='width: 150px;'>Operating system</td>"
	x += "<td style='width: 100px;'>Threat info</td>"
        x += "<td style='width: 100px;'>Reported at</td>"
        x += "<td style='width: 100px;'>Matched at</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in alerts[:10]:
		x += "<tr>"
		(ret, response_code, response_data) = hx_api_object.restGetHostSummary(str(entry['agent']['_id']))
		x += "<td><a class='hostLink' href='/hosts?host=" + str(response_data['data']['_id']) + "'>" + str(response_data['data']['hostname']) + "</a></td>"
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

def formatAlertsTable(alerts, hx_api_object, profileid, c, conn):

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
		annotations = sqlGetAnnotationStats(c, conn, str(entry['_id']), profileid)
		
		if (annotations[0][1] == 1):
			bgcolor = "#fffce0"
		elif (annotations[0][1] == 2):
			bgcolor = "#e0ffe3"
		else:
			bgcolor = "#ffffff"
	
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
		if (annotations[0][1] == 1):
			x += "<td style='text-align: center; background: " + bgcolor + ";'>Investigating</td>"
		elif (annotations[0][1] == 2):
			x += "<td style='text-align: center; background: " + bgcolor + ";'>Completed</td>"
		else:
			x += "<td style='text-align: center; background: " + bgcolor + ";'>New</td>"
			
		# Annotation status
		x += "<td style='text-align: center;'>"
			
		x += "<a href='#' id='adisp_" + str(entry['_id']) + "' class='tableActionButton'>show (" + str(annotations[0][0]) + ")</a>"
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


	for item in an:
	
		atext = "<br />".join(item[0].split("\n"))
	
		x += "<tr>"
		x += "<td>" + str(item[2]) + "</td>"
		x += "<td>" + str(item[3]) + "</td>"
		x += "<td>" + atext + "</td>"
		x += "<td>"
		
		if item[1] == 1:
			x += "Investigating"
		elif item[1] == 2:
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
	

def formatProfCredsInfo(c, conn, profileid):

	x = ""
	
	data = sqlGetProfCredTable(c, conn, profileid)
	
	if len(data) > 0:
		x += "Background processing credentials are set <a href='/settings?unsetprofcreds=" + profileid + "'>Unset</a>"
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
	
def formatStackTable(c, conn, profileid, hs):

	x = ""
	
	data = sqlGetStackJobsProfile(c, conn, profileid)
	
	x += "<table id='stacktable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>ID</td>"
	x += "<td>Created</td>"
	x += "<td>Last updated</td>"
	x += "<td>Type</td>"
	x += "<td>State</td>"
	x += "<td>Profile ID</td>"
	x += "<td>HX Bulk ID</td>"
	x += "<td>Hostset</td>"
	x += "<td style='width: 160px;'>Completion rate</td>"
	x += "<td style='width: 260px;'>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in data:
		x += "<tr>"
		x += "<td>" + str(entry[0]) + "</td>"
		x += "<td>" + str(entry[1]) + "</td>"
		x += "<td>" + str(entry[2]) + "</td>"
		x += "<td>" + str(entry[3]) + "</td>"
		x += "<td>" + str(entry[4]) + "</td>"
		x += "<td>" + str(entry[5]) + "</td>"
		x += "<td>" + str(entry[6]) + "</td>"
		
		# Host set
		for hsentry in hs['data']['entries']:
			if hsentry['_id'] == entry[7]:
				hsname = hsentry['name']
				hstype = hsentry['type']
				
		x += "<td>" + hsname + " - (" + hstype + ")" + "</td>"
		
		# Completion rate
		x += "<td>"
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + str(entry[0]) + "' data-percent='" + str(entry[8]) + "'></div></div>"
		x += "</td>"
		
		# Actions
		x += "<td>"
		x += "<a href='/stacking?stop=" +  str(entry[0]) + "' style='margin-right: 10px;' class='tableActionButton'>stop</a>"
		x += "<a href='/stacking?remove=" +  str(entry[0]) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		x += "<a href='/stackinganalyze?id=" +  str(entry[0]) + "' style='margin-right: 10px;' class='tableActionButton'>analyze</a>"
		x += "</td>"
		x += "</tr>"
	
	x += "</tbody>"
	x += "</table>"

	return(x)

def formatServiceMD5StackData(stacktable):

	x = ""

	x += "<table id='svcmd5' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td>Count</td>"
	x += "<td>Hostname</td>"
	x += "<td>Name</td>"
	x += "<td>Path</td>"
	x += "<td>Path MD5</td>"
	x += "<td>Service DLL</td>"
	x += "<td>Service DLL MD5</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in stacktable:
		x += "<tr>"
		x += "<td>" + str(entry[0]) + "</td>"
		# Name of endpoint
		if (entry[0] == 1):
			x += "<td>" + str(entry[6]) + "</td>"
		else:
			x += "<td>Multiple</td>"
		x += "<td>" + str(entry[1]) + "</td>"
		x += "<td>" + str(entry[2]) + "</td>"
		x += "<td>" + str(entry[3]) + "</td>"
		x += "<td>" + str(entry[4]) + "</td>"
		x += "<td>" + str(entry[5]) + "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	
	return(x)

	
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
	x += "<td style='width: 500px; padding: 0; vertical-align: top; border-right: 0;'>"
	
	# Sub alert table start
	x += "<table id='hostAlertTable' class='genericTable' style='width: 100%; border-top: none; border-right: 1px solid #dddddd; border-left: 1px solid #dddddd;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='padding: 3px; font-weight: bold; text-align: center;'>type</td>"
	x += "<td style='padding: 3px; font-weight: bold; '>name</td>"
	x += "<td style='padding: 3px; font-weight: bold; text-align: center;'>time</td>"
	x += "<td style='padding: 3px; font-weight: bold; text-align: center;'>action</td>"
	x += "</tr>"
	x += "</thead>"

	(aret, aresponse_code, aresponse_data) = hx_api_object.restGetAlertsHost(response_data['data']['_id'])
	if aret:
		for alert in aresponse_data:
			x += "<tr class='clickable-row' id='alert_" + str(alert['_id']) + "'>"
					
			x += "<td style='text-align: center; width: 40px; padding: 3px;;'>"
			if str(alert['source']) == "EXD":
				x += "<div class='tableActionIcon'>EXD</div>"
			elif (str(alert['source']) == "MAL"):
				x += "<div class='tableActionIcon'>MAL</div>"
			elif (str(alert['source']) == "IOC"):
				x += "<div class='tableActionIcon'>IOC</div>"
			else:
				x +="N/A"
			x += "</td>"
						
			x += "<td style='padding: 3px;'>"
			
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
					x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px; margin-left: 20px;'>"
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
				x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-left: 20px;'>"
				x += "<tr><td style='width: 150px;'>Initial exploit timestamp</td><td>" + alert['event_values']['earliest_detection_time'] + "</td></tr>"
				x += "<tr><td style='width: 150px;'>Process path</td><td>" + alert['event_values']['process_name'] + "</td></tr>"
				x += "<tr><td style='width: 150px;'>Process ID</td><td>" + alert['event_values']['process_id'] + "</td></tr>"
				x += "</table>"
				x += "</div>"
			
			# MAL
			elif str(alert['source']) == "MAL":
				x += alert['event_values']['detections']['detection'][0]['infection']['infection-name']
			
				# Alert details hidden div
				x += "<div style='display: none;' id='alertdetails_" + str(alert['_id']) + "'>"
				x += "<div class='tableTitle'>Malware alert: " + alert['event_values']['detections']['detection'][0]['infection']['infection-type'] + "</div>"
				x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
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
			
			
			x += "<td style='text-align: center; width: 90px; padding: 3px;'>"
			import datetime
			t = HXAPI.gt(alert['reported_at'])
			x += HXAPI.prettyTime(t)
			x += "</td>"
			
	
			x += "<td style='text-align: center; width: 60px; padding: 3px;'>"
			x += str(alert['resolution'])
			x += "</td>"
			
			x += "</tr>"
	x += "</table>"
	# Sub alert table stop
	
	x += "</td>"
	x += "<td id='alertcontent' style='vertical-align: top; padding: 30px; padding-top: 15px;'>"
	x += "</td>"
	x += "</tr>"
	
	# Alerts context view
	
	# Acquisitions
	
	
	x += "</table>"
	
	return(x)