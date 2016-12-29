
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


def formatBulkTable(bulktable):

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
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in bulktable['data']['entries']:

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
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
			x += "<a href='/bulkdownload?id=" + str(entry['result']['url']) + "'>Download acquisition</a>"
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
	x += "<td style='width: 100px;'>Active since</td>"
	x += "<td style='width: 150px;'>Created by</td>"
	x += "<td style='width: 140px;'>Category</td>"
	x += "<td style='width: 170px;'>Active conditions</td>"
	x += "<td style='width: 170px;'>Hosts with alerts</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in iocs['data']['entries']:
		x += "<tr>"
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

def formatCategoriesSelect(cats):

	x = "<select name='cats' id='cats'>"
	for entry in cats['data']['entries']:
		x += "<option value='" + entry['uri_name'] + "'>" + entry['name']
	x += "</select>"
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
        x += "<td style='width: 100px;'>Event type</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in alerts['data']['entries'][:10]:
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
		x += "<td>" + str(entry['event_type']) + "</td>"
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"

	return(x)

def formatAlertsTable(alerts, fetoken, hxip, hxport, profileid, c, conn):

	x = "<table id='alertsTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 50px;'>OS</td>"
	x += "<td style='width: 100px;'>Host</td>"
	x += "<td style='width: 120px;'>Domain</td>"
	x += "<td style='width: 100px;'>Alerted</td>"
	x += "<td style='width: 150px;'>Reported at</td>"
	x += "<td style='width: 150px;'>Matched at</td>"
	x += "<td style='width: 140px;'>Event badge</td>"
	x += "<td style=''>Event type</td>"
	x += "<td style='width: 70px; text-align: center;'>Annotations</td>"
	x += "<td style='width: 100px;'>Actions</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"

	# print alerts['data']['entries'][0]
	
	for entry in alerts['data']['entries']:
		x += "<tr>"
	
		hostinfo = restGetHostSummary(fetoken, str(entry['agent']['_id']), hxip, hxport)
		#x += "<td>" + str(hostinfo['data']['os']['product_name']) + " " + str(hostinfo['data']['os']['patch_level']) + " " + str(hostinfo['data']['os']['bitness']) + "</td>"
		
		# OS
		x += "<td>"
		if str(hostinfo['data']['os']['product_name']).startswith('Windows'):
			x += "<img style='width: 40px;' src='/static/ico/windows.svg'>"
		else:
			x += "<img style='width: 40px;' src='/static/ico/apple.svg'>"
		x += "</td>"
		
		# Host
		x += "<td>" + str(hostinfo['data']['hostname']) + "</td>"
		
		# Domain
		x += "<td>" + str(hostinfo['data']['domain']) + "</td>"
		
		# Alerted
		import datetime
		t = gt(entry['reported_at'])
		x += "<td>" + prettyTime(t) + "</td>"

		# Reported at
		x += "<td>" + str(entry['reported_at']) + "</td>"
		
		# Matched at
		x += "<td>" + str(entry['matched_at']) + "</td>"
		
		# Event badge
		x += "<td>"
		if (entry['source'] == "EXD"):
			x += "<img style='width: 40px;' src='/static/ico/XPLT-Blue.svg'>"
		elif (entry['source'] == "IOC"):
			x += "<img style='width: 40px;' src='/static/ico/PRS-Blue.svg'> or <img style='width: 40px;' src='/static/ico/EXC-Blue.svg'>"
		else:
			x += "Unknown"
		x += "</td>"
		
		# Event type
		x += "<td>"
		if str(entry['source']) == "EXD":	
			x += "<u>Exploit behavior in: (" + str(entry['event_values']['process_id']) + ") " + str(entry['event_values']['process_name']) + " - (" + str(len(entry['event_values']['messages'])) + ")</u><br>"
			x += "<div style='margin-left: 20px; margin-top: 5px;'>"
			for behavior in entry['event_values']['messages']:
				x += behavior + "<br>"
			x += "</div>"
		else:
			indicators = restGetIndicatorFromCondition(fetoken, str(entry['condition']['_id']), hxip, hxport)
			for indicator in indicators['data']['entries']:
				x += "<u>Indicator hit: " + indicator['name'] + " (" + indicator['category']['name'] + ")</u><br>"
			x += "<div style='margin-left: 20px; margin-top: 5px;'>"
			x += str(entry['event_type'])
			x += "</div>"
		x += "</td>"
		
		# Annotation status
		x += "<td style='text-align: center;'>"
		annotations = sqlGetAnnotationStats(c, conn, str(entry['_id']), profileid)
		if (annotations[0][1] == 1):
			x += "<div class='alertStatus alertStatusInv'>Investigating - " + str(annotations[0][0]) + "</div>"
		elif (annotations[0][1] == 2):
			x += "<div class='alertStatus alertStatusCom'>Completed - " + str(annotations[0][0]) + "</div>"
		else:
			x += "<div class='alertStatus alertStatusNew'>New - " + str(annotations[0][0]) + "</div>"
		x += "</td>"
		
		# Actions
		x += "<td>"
		x += "<input id='annotate_" + str(entry['_id']) + "' type='button' value='Annotate'>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
        x += "</table>"

        return(x)


