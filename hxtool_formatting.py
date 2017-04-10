
from hx_lib import *
from hxtool_db import *

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
	x += "<td>Actions</td>"
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
	x += "<td style='width: 100px;'>type</td>"
	x += "<td>data</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in hostresults['data']['entries']:
		for result in entry['results']:
			x += "<tr>"
			x += "<td>" + entry['host']['hostname'] + "</td>"
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
        x += "<td>% Complete</td>"
        x += "<td>Actions</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in bulktable['data']['entries']:

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
		if total_size == 0:
			completerate = float(0.0)
		else:
			completerate = (entry['stats']['running_state']['COMPLETE'] / float(total_size)) * 100

		x += "<tr class='clickable-row' data-href='/bulkdetails?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>" + str(entry['host_set']['name']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['NEW']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['ABORTED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['DELETED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['REFRESH']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['CANCELLED']) + "</td>"
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
	x += "<td style='width: 140px;'>Category</td>"
	x += "<td style='width: 170px;'>Active conditions</td>"
	x += "<td style='width: 170px;'>Hosts with alerts</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in iocs['data']['entries']:
		x += "<tr class='clickable-row' data-value='" + str(entry['category']['name']) + "___" + str(entry['uri_name']) + "'>"
		x += "<td><input type='checkbox' name='ioc___" + str(entry['display_name']) + "___" + str(entry['category']['name']) + "' value='" + str(entry['uri_name']) + "'></td>"
		x += "<td>" + str(entry['name']) + "</td>"
		x += "<td>" + str(entry['active_since']) + "</td>"
		x += "<td>" + str(entry['create_actor']['username']) + "</td>"
		x += "<td>" + str(entry['category']['name']) + "</td>"
		x += "<td>" + str(entry['stats']['active_conditions']) + "</td>"
		x += "<td>" + str(entry['stats']['alerted_agents']) + "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatConditions(cond_pre, cond_ex):
	
	x = ""
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
	
def formatDashAlerts(alerts, fetoken, hxip, hxport):

	x = "<table id='dashAlerts' class='dashAlerts' style='width: 100%;'>"
        x += "<thead>"
        x += "<tr>"
        x += "<td style='width: 100px;'>Host</td>"
        x += "<td style='width: 100px;'>Domain</td>"
        x += "<td style='width: 100px;'>Operating system</td>"
	x += "<td style='width: 100px;'>Threat info</td>"
        x += "<td style='width: 100px;'>Reported at</td>"
        x += "<td style='width: 100px;'>Matched at</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in alerts[:10]:
		x += "<tr>"
		hostinfo = restGetHostSummary(fetoken, str(entry['agent']['_id']), hxip, hxport)
		x += "<td>" + str(hostinfo['data']['hostname']) + "</td>"
		x += "<td>" + str(hostinfo['data']['domain']) + "</td>"
		x += "<td>" + str(hostinfo['data']['os']['product_name']) + " " + str(hostinfo['data']['os']['patch_level']) + " " + str(hostinfo['data']['os']['bitness']) + "</td>"
		x += "<td>"
		if str(entry['source']) == "IOC":
			indicators = restGetIndicatorFromCondition(fetoken, str(entry['condition']['_id']), hxip, hxport)
			for indicator in indicators['data']['entries']:
				x += "<b>Indicator:</b> " + indicator['name'] + " (" + indicator['category']['name'] + ")<br>"
		else:
			x += "<b>Exploit:</b> " + str(len(entry['event_values']['messages'])) + " malicous behaviors"
		x += "</td>"
		x += "<td>" + str(entry['reported_at']) + "</td>"
		x += "<td>" + str(entry['matched_at']) + "</td>"
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"

	return(x)

def formatAlertsTable(alerts, fetoken, hxip, hxport, profileid, c, conn):

	x = "<table id='alertsTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 40px;'>OS</td>"
	x += "<td style='width: 100px;'>Host</td>"
	x += "<td style='width: 120px;'>Domain</td>"
	x += "<td style='width: 100px; text-align: center;'>Alerted</td>"
	x += "<td style='width: 150px;'>Reported at</td>"
	x += "<td style='width: 150px;'>Matched at</td>"
	x += "<td style='width: 100px; text-align: center;'>Containment</td>"
	x += "<td style=''>Event type</td>"
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
	
		hostinfo = restGetHostSummary(fetoken, str(entry['agent']['_id']), hxip, hxport)
		
		# OS
		x += "<td>"
		if str(hostinfo['data']['os']['product_name']).startswith('Windows'):
			x += "<img style='width: 30px;' src='/static/ico/windows.svg'>"
		else:
			x += "<img style='width: 30px;' src='/static/ico/apple.svg'>"
		x += "</td>"
		
		# Host
		x += "<td>" + str(hostinfo['data']['hostname']) + "</td>"
		
		# Domain
		x += "<td>" + str(hostinfo['data']['domain']) + "</td>"
		
		# Alerted
		import datetime
		t = gt(entry['reported_at'])
		x += "<td style='text-align: center; font-weight: 700;'>" + prettyTime(t) + "</td>"

		# Reported at
		x += "<td>" + str(entry['reported_at']) + "</td>"
		
		# Matched at
		x += "<td>" + str(entry['matched_at']) + "</td>"
		
		# Containment state
		x += "<td style='text-align: center;'>"
		x += str(entry['agent']['containment_state'])
		x += "</td>"
		
		# Event type
		x += "<td>"
		x += "<a class='tableActionButton' id='showalert_" + str(entry['_id']) + "' style='color: #ffffff; padding-left: 5px; padding-right: 5px;' href='#'>&#x25BC;</a>"
		if str(entry['source']) == "EXD":	
			x += "Exploit behavior in application: (" + str(entry['event_values']['process_id']) + ") " + str(entry['event_values']['process_name']) + " - (" + str(len(entry['event_values']['messages'])) + ")"
			x += "<div class='alertDetailsDisplayPopupEXD' id='alertdetails_" + str(entry['_id']) + "'>"
			for behavior in entry['event_values']['messages']:
				x += behavior + "<br>"
			x += "<br>"
			x += "<input type='button' id='close_" + str(entry['_id']) + "' value='close'>"
			x += "</div>"
		else:
			indicators = restGetIndicatorFromCondition(fetoken, str(entry['condition']['_id']), hxip, hxport)
			for indicator in indicators['data']['entries']:
				x += "Intel hit - IOC: " + indicator['name'] + " (" + indicator['category']['name'] + ")"
			x += "<div class='alertDetailsDisplayPopup' id='alertdetails_" + str(entry['_id']) + "'>"
			x += "<div class='tableTitle'>Indicator type: " + str(entry['event_type']) + "</div>"
			x += "<table class='genericTable' style='margin-bottom: 15px;'>"
			for hitkey, hitdata in entry['event_values'].iteritems():
				x += "<tr><td>" + str(hitkey) + "</td><td>" + str(hitdata) + "</td></tr>"
				# x += str(hitkey) + ":" + str(hitdata) + "<br>"
			x += "</table>"
			x += "<input type='button' id='close_" + str(entry['_id']) + "' value='close'>"
			x += "</div>"
		
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
			
		x += "<a href='#' id='adisp_" + str(entry['_id']) + "' class='tableActionButton'>show - " + str(annotations[0][0]) + "</a>"
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

def formatAlertsCsv(alertsjson, fetoken, hxip, hxport):

	x = "reported_at;matched_at;event_at;hostname;domain;source;productname;event_type;event_id\r\n"
	
	for entry in alertsjson:
		hostinfo = restGetHostSummary(fetoken, str(entry['agent']['_id']), hxip, hxport)
		x += entry['reported_at'] + ";"
		x += entry['matched_at'] + ";"
		x += entry['event_at'] + ";"
		x += hostinfo['data']['hostname'] + ";"
		x += hostinfo['data']['domain'] + ";"
		x += str(entry['source']) + ";"
		x += hostinfo['data']['os']['product_name'] + " " + hostinfo['data']['os']['patch_level'] + " " + hostinfo['data']['os']['bitness'] + ";"
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
		x += "<input name='bgpass' type='text'>"
		x += "<br><input style='margin-top: 15px;' class='tableActionButton' type='submit' value='set'>"
		x += "</form>"
	
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
	x += "<td>Completion rate</td>"
	x += "<td>Actions</td>"
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
		
		for hsentry in hs['data']['entries']:
			if hsentry['_id'] == entry[7]:
				hsname = hsentry['name']
				hstype = hsentry['type']
				
		x += "<td>" + hsname + " - (" + hstype + ")" + "</td>"
		x += "<td>" + str(entry[8]) + "%</td>"
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
