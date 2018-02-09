
from hxtool_config import *
from hx_lib import *
from hxtool_db import *
import time

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
		
		x += "<tr class='clickable-row' data-href='/bulkdetails?id=" + HXAPI.compat_str(entry['_id']) + "'>"
		x += "<td>" + HXAPI.compat_str(entry['_id']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['state']) + "</td>"
		hostset_id = ""
		if entry['host_set']:
			hostset_id = entry['host_set']['_id']
		elif entry['comment'] and 'hostset_id' in entry['comment']:
			hostset_id = json.loads(entry['comment'])['hostset_id']
		x += "<td>{0}</td>".format(hostset_id)
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['NEW']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['ABORTED']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['DELETED']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['REFRESH']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['running_state']['CANCELLED']) + "</td>"
		x += "<td>"

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
		if total_size == 0:
			completerate = 0
		else:
			completerate = int(float(entry['stats']['running_state']['COMPLETE']) / float(total_size) * 100)
		
		if completerate > 100:
			completerate = 100
		
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + HXAPI.compat_str(entry['_id']) + "' data-percent='" + HXAPI.compat_str(int(round(completerate))) + "'></div></div>"
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
			x += "<div class='htMyBar htBarWrap'><div class='htBar' id='prog_" + HXAPI.compat_str(entry['_id']) + "' data-percent='" + HXAPI.compat_str(dlprogress) + "'></div></div>"
			x += "</td>"
		else:
			x += "<td>N/A</td>"
			
		x += "<td>" 
		
		if bulk_download and bulk_download['post_download_handler']:
			x += "Post-download handler: {0}".format(bulk_download['post_download_handler'])
		else:
			x += "<a class='tableActionButton' href='/bulkaction?action=stop&id=" + HXAPI.compat_str(entry['_id']) + "'>stop</a>"
			x += "<a class='tableActionButton' href='/bulkaction?action=remove&id=" + HXAPI.compat_str(entry['_id']) + "'>remove</a>"
			if not bulk_download:
				x += "<a class='tableActionButton' href='/bulkaction?action=download&id=" + HXAPI.compat_str(entry['_id']) + "'>download</a>"
			else:
				x += "<a class='tableActionButton' href='/bulkaction?action=stopdownload&id=" + HXAPI.compat_str(entry['_id']) + "'>stop download</a>"
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
		x += "<td>" + HXAPI.compat_str(entry['host']['hostname']) + "</td>"
		#x += "<td>" + HXAPI.compat_str(entry['host']['_id']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['queued_at']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['complete_at']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['state']) + "</td>"
		x += "<td>"
		if HXAPI.compat_str(entry['state']) == "COMPLETE":
			x += "<a class='tableActionButton' href='/bulkdownload?id=" + HXAPI.compat_str(entry['result']['url']) + "'>Download acquisition</a>"
		x += "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatIOCResults(iocs, mycategories):

	x = "<table id='iocTable' class='genericTable' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr>"
	x += "<td style='width: 20px;'>&nbsp;</td>"
	x += "<td>Name</td>"
	x += "<td style='width: 180px;'>Active since</td>"
	x += "<td style='width: 100px;'>Created by</td>"
	x += "<td style='width: 200px;'>Category</td>"
	x += "<td style='width: 80px;'>Platforms</td>"
	x += "<td style='width: 80px;'>Conditions</td>"
	x += "<td style='width: 60px;'>Hosts</td>"
	x += "<td style='width: 60px;'>Action</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"
	
	for entry in iocs['data']['entries']:

		p = ""
		for platform in entry['platforms']:
			p += platform + ","
		p = p[:-1]
		
		x += "<tr data-value='" + HXAPI.compat_str(entry['category']['uri_name']) + "___" + HXAPI.compat_str(entry['uri_name']) + "'>"
		x += "<td><input type='checkbox' name='ioc___" + HXAPI.compat_str(entry['display_name']) + "___" + HXAPI.compat_str(entry['category']['uri_name']) + "___" + HXAPI.compat_str(p) + "' value='" + HXAPI.compat_str(entry['uri_name']) + "'></td>"
		x += "<td>" + HXAPI.compat_str(entry['name']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['active_since']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['create_actor']['username']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['category']['name']) + "</td>"
		x += "<td>"
		for platform in entry['platforms']:
			x += HXAPI.compat_str(platform) + "&nbsp"
		x += "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['active_conditions']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['stats']['alerted_agents']) + "</td>"
		x += "<td>"
		if (mycategories[entry['category']['_id']] in ['full', 'edit_delete']):
			x += "<a class='tableActionButton' href='/rtioc?indicator=" + HXAPI.compat_str(entry['uri_name']) + "'>edit</a>"
		x += "<button class='tableActionButton' id='iocview_{0}' data-id='{0}'>view</button>".format(entry['uri_name'])
		if not HXAPI.compat_str(entry['category']['name']) == "Custom":
			# Cant clone to custom if the category is already custom
			x += "<a class='tableActionButton' href='/rtioc?indicator=" + HXAPI.compat_str(entry['uri_name']) + "&clone=true'>clone</a>"
		if (mycategories[entry['category']['_id']] in ['full', 'edit_delete', 'delete']):
			x += "<a class='tableActionButton' href='/rtioc?delete=" + HXAPI.compat_str(entry['uri_name']) + "&category=" + HXAPI.compat_str(entry['category']['name']) + "' onclick=\"return confirm('Are you sure?')\">delete</a>"
		x += "</td>"
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
				if 'negate' in test and 'preservecase' in test:
					x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>preservecase(" + test['value'] + ")</b></li>"
				elif 'negate' in test:
					x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
				elif 'preservecase' in test:
					x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>preservecase(" + test['value'] + ")</b></li>"
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
				if 'negate' in test and 'preservecase' in test:
					x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>preservecase(" + test['value'] + ")</b></li>"
				elif 'negate' in test:
					x += "<li style=''>" + test['token'] + " <i><span style='color: red; font-weight: 700;'>not</span> " + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
				elif 'preservecase' in test:
					x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>preservecase(" + test['value'] + ")</b></li>"
				else:
					x += "<li style=''>" + test['token'] + " <i>" + test['operator'] + "</i> <b>" + test['value'] + "</b></li>"
			x += "</ul>"
			x += "</li>"
		
		x += "</ul>"
		x += "</li>"
		x += "</div>"
		
	return (x)
	
def formatCategoriesSelect(cats, setdefault="Custom"):

	x = "<select name='cats' id='cats'>"
	for entry in cats['data']['entries']:
		if entry['name'] == setdefault:
			x += "<option value='" + entry['uri_name'] + "' selected>" + entry['name']
		else:
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
		x += "<td>" + HXAPI.compat_str(entry['name']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['retention_policy']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['ui_edit_policy']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['ui_source_alerts_enabled']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['ui_signature_enabled']) + "</td>"
		x += "</tr>"
		
	x += "</tbody>"
	x += "</table>"
	
	return(x)
	
def formatHostsets(hs):
	# The hidden/secret All Hosts host set
	x = "<option value='9'>All Hosts"
	
	for entry in hs['data']['entries']:
		x += "<option value='" + HXAPI.compat_str(entry['_id']) + "'>" + entry['name']
	
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
			x += "<td>" + HXAPI.compat_str(item['create_timestamp']) + "</td>"
			x += "<td>" + HXAPI.compat_str(item['create_user']) + "</td>"
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
		x += "<tr class='clickable-row' data-href='/channelinfo?id=" + HXAPI.compat_str(entry['_id']) + "'>"
		x += "<td>" + HXAPI.compat_str(entry['name']) + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['description']) + "</td>"
		x += "<td>" + entry['create_time'] + "<//td>"
		x += "<td>" + entry['create_actor']['username'] + "</td>"
		x += "<td>" + HXAPI.compat_str(entry['priority']) + "</td>"
		x += "<td>"
		for hset in entry['host_sets']:
			x += hset['name'] + "<br>"
		x += "</td>"
		x += "<td>"
		x += "<a href='/channels?delete=" +  HXAPI.compat_str(entry['_id']) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
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
		x += "<td>" + HXAPI.compat_str(job.eid) + "</td>"
		x += "<td>" + HXAPI.compat_str(job['create_timestamp']) + "</td>"
		x += "<td>" + HXAPI.compat_str(job['update_timestamp']) + "</td>"
		x += "<td>" + job['stack_type'] + "</td>"
		x += "<td>" + ("STOPPED" if job['stopped'] else "RUNNING") + "</td>"
		x += "<td>" + HXAPI.compat_str(job['profile_id'])	+ "</td>"
		x += "<td>" + HXAPI.compat_str(job['bulk_download_id']) + "</td>"		
		x += "<td>" + HXAPI.compat_str(bulk_download['hostset_id']) + "</td>"
		
		# Completion rate
		job_progress = 0
		if 'hosts' in job:
			hosts_completed = len([_ for _ in job['hosts'] if _['processed']])
		else:
			hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
		job_progress = int(hosts_completed / float(len(bulk_download['hosts'])) * 100)
		x += "<td>"
		x += "<div class='htMyBar htBarWrap'><div class='htBar' id='crate_" + HXAPI.compat_str(job.eid) + "' data-percent='" + HXAPI.compat_str(job_progress) + "'></div></div>"
		x += "</td>"
		
		# Actions
		x += "<td>"
		x += "<a href='/stacking?stop=" +  HXAPI.compat_str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>stop</a>"
		x += "<a href='/stacking?remove=" +  HXAPI.compat_str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>remove</a>"
		x += "<a href='/stackinganalyze?id=" +  HXAPI.compat_str(job.eid) + "' style='margin-right: 10px;' class='tableActionButton'>analyze</a>"
		x += "</td>"
		x += "</tr>"
	
	x += "</tbody>"
	x += "</table>"

	return(x)

	
# This is the alert investigation viewer
def formatHostInfo(response_data, hx_api_object):

	x = ""

	x += "<table id='hostinfo' class='genericTable' style='width: 100%; border: 0; margin: 0;'>"
	x += "<tbody>"
	x += "<tr style='border: 0;'>"

	# First box
	x += "<td colspan='2' style='width: 100%; border: 0; padding: 0;'>"
	
	
	# HOSTINFO
	x += "<table class='genericTable' style='width: 100%; border: 1px solid #dddddd; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200);'>"
	x += "<tr>"
	
	x += "<td style='vertical-align: center; text-align: center; width: 60px;'>"
	if HXAPI.compat_str(response_data['data']['os']['product_name']).startswith('Windows'):
		x += "<img style='width: 50px;' src='/static/ico/windows.svg'>"
	else:
		x += "<img style='width: 50px;' src='/static/ico/apple.svg'>"
	x += "</td>"
	
	x += "<td style='font-size: 14px; width: 406px;'>"
	x += "<div style='font-weight: bold; font-size: 20px;'>" + HXAPI.compat_str(response_data['data']['hostname'])  + "</div>" 
	x += HXAPI.compat_str(response_data['data']['domain']) + "<br>"
	x += HXAPI.compat_str(response_data['data']['os']['product_name']) + " " + HXAPI.compat_str(response_data['data']['os']['patch_level']) + " " + HXAPI.compat_str(response_data['data']['os']['bitness']) + "<br>"
	x += HXAPI.compat_str(response_data['data']['agent_version']) + "<br>"
	x += "</td>"
	
	x += "<td rowspan='2' style='vertical-align: top; width: auto;'>"
	x += "<b>Timezone: </b> " + HXAPI.compat_str(response_data['data']['timezone']) + "<br>"
	t = HXAPI.gt(response_data['data']['last_poll_timestamp'])
	x += "<b>Last poll Timestamp: </b> " + HXAPI.compat_str(response_data['data']['last_poll_timestamp']) + " (" + HXAPI.prettyTime(t) + ")<br>"
	x += "<b>Last poll IP: </b> " + HXAPI.compat_str(response_data['data']['last_poll_ip']) + "<br>"

	(sret, sresponse_code, sresponse_data) = hx_api_object.restGetHostSysinfo(HXAPI.compat_str(response_data['data']['_id']))
	if sret:
		x += "<b>Primary IP: </b> " + HXAPI.compat_str(sresponse_data['data']['primaryIpAddress']) + "<br>"
		t = HXAPI.gtNoUs(sresponse_data['data']['installDate'])
		x += "<b>Installed: </b> " + HXAPI.compat_str(sresponse_data['data']['installDate']) + " (" + HXAPI.prettyTime(t) + ")<br>"
		x += "<b>Processor: </b> " + HXAPI.compat_str(sresponse_data['data']['processor']) + "<br>"
		x += "<b>Memory Available: </b> " + HXAPI.compat_str(round(int(sresponse_data['data']['availphysical']) / 1024 / 1024 / 1024, 2)) + " GB / "
		x += HXAPI.compat_str(round(int(sresponse_data['data']['totalphysical']) / 1024 / 1024 / 1024, 2)) + " GB<br>"
		
		x += "<b>Logged on user(s): </b> " + HXAPI.compat_str(sresponse_data['data']['loggedOnUser']) + "<br>"

	x += "</td>"
	
	x += "<td rowspan='2' style='width: 80px; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['alerting_conditions']) + "</span><br>Alerting conditions</td>"
	x += "<td rowspan='2' style='width: 80px; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['exploit_alerts']) + "</span><br>Exploit alerts</td>"
	x += "<td rowspan='2' style='width: 80px; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['acqs']) + "</span><br>Acquisitions</td>"
	x += "<td rowspan='2' style='width: 80px; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['alerts']) + "</span><br>Alerts</td>"
	x += "<td rowspan='2' style='width: 80px; border-right: 1px solid #dddddd; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['exploit_blocks']) + "</span><br>Exploit blocks</td>"
	x += "<td rowspan='2' style='width: 80px; text-align: center;'><span style='font-size: 22px; font-weight: bold;'>" + HXAPI.compat_str(response_data['data']['stats']['malware_alerts']) + "</span><br>Malware alerts</td>"

	
	x += "</tr>"
	x += "<tr><td colspan='2'>"
	
	x += "<div style='padding-top: 10px; padding-bottom: 10px;'>"
	if response_data['data']['containment_state'] == "contained":
		x += "<a class='tableActionButton' id='uncontain_" + HXAPI.compat_str(response_data['data']['_id']) + "'>uncontain</a>"
	elif (response_data['data']['containment_state'] == "normal") and (response_data['data']['containment_queued'] == False):
		x += "<a class='tableActionButton' id='contain_" + HXAPI.compat_str(response_data['data']['_id']) + "'>contain</a>"
	elif (response_data['data']['containment_state'] == "normal") and (response_data['data']['containment_queued'] == True):
		x += "<a class='tableActionButton' id='appcontain_" + HXAPI.compat_str(response_data['data']['_id']) + "'>approve containment</a>"
	
	x += "<a class='tableActionButton' id='triage_" + HXAPI.compat_str(response_data['data']['_id']) + "'>triage</a>"
	x += "<a class='tableActionButton' id='fileaq_" + HXAPI.compat_str(response_data['data']['_id']) + "'>file acq</a>"
	x += "<a class='tableActionButton' id='acq_" + HXAPI.compat_str(response_data['data']['_id']) + "'>acquisition</a>"
	x += "</div>"
	
	x += "</td></tr>"
	x += "</table>"
	# HOSTINFO END

	
	x += "</td>"
	x += "</tr>"
	
	# Alerts view
	x += "<tr style='border-bottom: none;'>"
	x += "<td style='width: auto; padding: 0; vertical-align: top; border-right: 0; border-bottom: none; padding-right: 0;'>"
	
	# Sub alert table start
	x += "<table id='hostAlertTable' class='genericTable genericTableSmall' style='width: 500px; border-right: 1px solid #dddddd; border-left: 1px solid #dddddd; margin-top: 15px; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200); margin-bottom: 20px;'>"
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
			x += "<tr class='clickable-row' id='alert_" + HXAPI.compat_str(alert['_id']) + "'>"
					
			x += "<td style='text-align: center; width: 40px;'>"
			if HXAPI.compat_str(alert['source']) == "EXD":
				x += "<div class='tableActionIcon'>EXD</div>"
			elif (HXAPI.compat_str(alert['source']) == "MAL"):
				x += "<div class='tableActionIcon'>MAL</div>"
			elif (HXAPI.compat_str(alert['source']) == "IOC"):
				x += "<div class='tableActionIcon'>IOC</div>"
			else:
				x +="N/A"
			x += "</td>"
						
			x += "<td>"
			
			# IOC
			if HXAPI.compat_str(alert['source']) == "IOC":
				(iret, iresponse_code, iresponse_data) = hx_api_object.restGetIndicatorFromCondition(HXAPI.compat_str(alert['condition']['_id']))
				if iret:
					for indicator in iresponse_data['data']['entries']:
						x += indicator['name']
					
					# Alert details hidden div
					x += "<div style='display: none;' id='alertdetails_" + HXAPI.compat_str(alert['_id']) + "'>"
					
					(cret, cresponse_code, cresponse_data) = hx_api_object.restGetConditionDetails(HXAPI.compat_str(alert['condition']['_id']))
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
		
					
					x += "<div class='tableTitle'>Indicator type: " + HXAPI.compat_str(alert['event_type']) + "</div>"
					x += "<table class='genericTable genericTableSmall' style='width: 100%; margin-bottom: 15px;'>"
					for hitkey, hitdata in alert['event_values'].items():
						if "md5" in hitkey:
							x += "<tr>"
							x += "<td style='width: 300px;'>" + HXAPI.compat_str(hitkey) + "</td>"
							x += "<td>"
							x += HXAPI.compat_str(hitdata)
							x += "<a class='tableActionButton' target='_newtab' style='margin-left: 10px; font-size: 9px;' href='https://www.virustotal.com/#/file/" + HXAPI.compat_str(hitdata) + "/detection'>virustotal</a>"
							x += "<a class='tableActionButton' target='_newtab' style='font-size: 9px;' href='https://intelligence.fireeye.com/search.html?search=" + HXAPI.compat_str(hitdata) + "'>isight</a>"
							x += "</td>"
							x += "</tr>"
						else:
							x += "<tr><td style='width: 300px;'>" + HXAPI.compat_str(hitkey) + "</td><td>" + HXAPI.compat_str(hitdata) + "</td></tr>"
					x += "</table>"
					x += "</div>"
			
			# EXG
			elif HXAPI.compat_str(alert['source']) == "EXD":
				x += HXAPI.compat_str(alert['event_values']['process_name']) + " (pid: " + HXAPI.compat_str(alert['event_values']['process_id']) + ")"
			
				# Alert details hidden div
				x += "<div style='display: none;' id='alertdetails_" + HXAPI.compat_str(alert['_id']) + "'>"
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
						for itemkey, itemdata in data[data['detail_type']].items():
							
							if itemdata != "N/A" and itemkey not in skiplist:
								x += "<tr>"
								if type(itemdata) is dict:
									x += "<td colspan='2'>"
									x += "<div class='clt'>"
									x += HXAPI.compat_str(itemkey)
									x += "<ul style='margin-top: 0;'>"
									for dictkey, dictdetail in itemdata.items():
										if 'md5' in dictkey:
											x += "<li>" + HXAPI.compat_str(dictkey) + ": " + HXAPI.compat_str(dictdetail)
											x += "<a class='tableActionButton' target='_newtab' style='padding-top: 1px; padding-bottom: 1px; margin-left: 10px; font-size: 9px;' href='https://www.virustotal.com/#/file/" + HXAPI.compat_str(dictdetail) + "/detection'>virustotal</a>"
											x += "<a class='tableActionButton' target='_newtab' style='padding-top: 1px; padding-bottom: 1px; font-size: 9px;' href='https://intelligence.fireeye.com/search.html?search=" + HXAPI.compat_str(dictdetail) + "'>isight</a>"
											x += "</li>"
										else:
											x += "<li>" + HXAPI.compat_str(dictkey) + ": " + HXAPI.compat_str(dictdetail) + "</li>"
									x += "</ul>"
									x += "</div>"
									x += "</td>"
								else:
									x += "<td style='width: 100px;'>" + HXAPI.compat_str(itemkey) + "</td>"
									x += "<td>" + HXAPI.compat_str(itemdata) + "</td>"
								
								x += "</tr>"
						x += "</table>"
						
							
						x += "</td>"
						x += "</tr>"
				x += "</table>"
				
					
				x += "</div>"
			
			# MAL
			elif HXAPI.compat_str(alert['source']) == "MAL":
				x += alert['event_values']['detections']['detection'][0]['infection']['infection-name']
			
				# Alert details hidden div
				x += "<div style='display: none;' id='alertdetails_" + HXAPI.compat_str(alert['_id']) + "'>"
				x += "<div class='tableTitle'>Malware alert: " + alert['event_values']['detections']['detection'][0]['infection']['infection-type'] + "</div>"
				x += "<table class='genericTable genericTableSmall' style='width: 100%;'>"
				for hitkey, hitdata in alert['event_values']['detections']['detection'][0]['infection'].items():
					x += "<tr><td>" + HXAPI.compat_str(hitkey) + "</td><td>" + HXAPI.compat_str(hitdata) + "</td></tr>"
				for hitkey, hitdata in alert['event_values']['detections']['detection'][0]['infected-object']['file-object'].items():
					x += "<tr>"
					x += "<td>"
					x += HXAPI.compat_str(hitkey)
					x += "</td>"
					x += "<td>"
					x += HXAPI.compat_str(hitdata)
					if any(word in hitkey for word in ["sha1", "md5"]):
						x += "<a class='tableActionButton' target='_newtab' style='margin-left: 10px; font-size: 9px;' href='https://www.virustotal.com/#/file/" + HXAPI.compat_str(hitdata) + "/detection'>VT</a>"
						x += "<a class='tableActionButton' target='_newtab' style='font-size: 9px;' href='https://intelligence.fireeye.com/search.html?search=" + HXAPI.compat_str(hitdata) + "'>iSight</a>"
					x += "</td>"
					x += "</tr>"
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
			x += HXAPI.compat_str(alert['resolution'])
			x += "</td>"
			
			x += "</tr>"
			
	x += "</table>"
	# Sub alert table stop
	
	x += "</td>"
	x += "<td style='vertical-align: top; padding-top: 15px; width: 100%; padding-right: 0;'>"
	x += "<div id='alertcontent' style='display: none; margin-left: 10px; margin-bottom: 15px; padding: 15px; border: 1px solid #dddddd; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200);'></div>"
	x += "</td>"
	x += "</tr>"
	
	# Alerts context view
	
	# Acquisitions
	
	x += "<tr>"
	x += "<td colspan='2' style='padding-left: 0; padding-right: 0;'>"

	(atret, atresponse_code, atresponse_data) = hx_api_object.restListTriageAcquisitionsHost(response_data['data']['_id'])
	
	if (atret):
		if (len(atresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>Triage acquisitions</div>"
			x += "<table class='genericTable  genericTableMedium' style='width: 100%; margin-bottom: 15px; border: 1px solid #dddddd; border-bottom: 0; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200);'>"
			x += "<thead>"
			x += "<tr>"
			x += "<td style='font-weight: bold;'>Acquisition</td>"
			x += "<td style='font-weight: bold;'>Requested by</td>"
			x += "<td style='font-weight: bold;'>Requested</td>"
			x += "<td style='font-weight: bold;'>Status</td>"
			x += "<td style='width: 100px; font-weight: bold;'>Action</td>"
			x += "</tr>"
			x += "<tbody>"
			for triage in atresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>"
				if triage['request_actor']['username'] == "automatic":
					x += "Automatic triage"
				else:
					x += "Normal triage"
				x += "</td>"
				x += "<td>" + HXAPI.compat_str(triage['request_actor']['username']) + "</td>"
				x += "<td>" + HXAPI.compat_str(triage['request_time']) + "</td>"
				x += "<td>" + HXAPI.compat_str(triage['state']) + "</td>"
				x += "<td><a href='/download?id=" + HXAPI.compat_str(triage['url']) + ".mans' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</tbody>"
			x += "</table>"

	(afret, afresponse_code, afresponse_data) = hx_api_object.restListFileAcquisitionsHost(response_data['data']['_id'])
	if (afret):
		if (len(afresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>File acquisitions</div>"
			x += "<table class='genericTable genericTableMedium' style='width: 100%; margin-bottom: 15px; border: 1px solid #dddddd; border-bottom: 0; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200);'>"
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
			x += "<tbody>"
			for fileaq in afresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>" + HXAPI.compat_str(fileaq['req_path']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['req_filename']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['request_actor']['username']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['request_time']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['zip_passphrase']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['state']) + "</td>"
				x += "<td>" + HXAPI.compat_str(fileaq['error_message']) + "</td>"
				x += "<td><a href='/download?id=" + HXAPI.compat_str(fileaq['url']) + ".zip' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</tbody>"
			x += "</table>"
		
	(adret, adresponse_code, adresponse_data) = hx_api_object.restListDataAcquisitionsHost(response_data['data']['_id'])
	if (adret):
		if (len(adresponse_data['data']['entries']) > 0):
			x += "<div class='tableTitle'>Data acquisitions</div>"
			x += "<table class='genericTable genericTableMedium' style='width: 100%; margin-bottom: 15px; border: 1px solid #dddddd; border-bottom: 0; border-radius: 3px; box-shadow: 2px 2px 5px rgb(200, 200, 200);'>"
			x += "<thead>"
			x += "<tr>"
			x += "<td style='font-weight: bold;'>Name</td>"
			x += "<td style='font-weight: bold;'>Requested by</td>"
			x += "<td style='font-weight: bold;'>Requested</td>"
			x += "<td style='font-weight: bold;'>Status</td>"			
			x += "<td style='width: 100px; font-weight: bold;'>Action</td>"
			x += "</tr>"
			x += "<tbody>"
			for daq in adresponse_data['data']['entries']:
				x += "<tr>"
				x += "<td>" + HXAPI.compat_str(daq['name']) + "</td>"
				x += "<td>" + HXAPI.compat_str(daq['request_actor']['username']) + "</td>"
				x += "<td>" + HXAPI.compat_str(daq['request_time']) + "</td>"
				x += "<td>" + HXAPI.compat_str(daq['state']) + "</td>"
				x += "<td><a href='/download?id=" + HXAPI.compat_str(daq['url']) + ".mans&content=json' class='tableActionButton'>download</a></td>"
				x += "</tr>"
			x += "</tbody>"
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
		x += "<td><a class='hostLink' href='/hosts?host=" + HXAPI.compat_str(host['_id']) + "'>" + HXAPI.compat_str(host['hostname']) + "</a></td>"
		x += "<td>" + HXAPI.compat_str(host['domain']) + "</td>"
		x += "<td>" + HXAPI.compat_str(host['primary_ip_address']) + "</td>"
		x += "<td>" + HXAPI.compat_str(host['last_poll_ip']) + "</td>"
		x += "<td>" + HXAPI.compat_str(host['last_poll_timestamp']) + "</td>"
		
		x += "<td>"
		if (host['containment_state'] == "normal") and (host['containment_queued'] == True):
			x += "requested"
		else:
			x += HXAPI.compat_str(host['containment_state'])
		x += "<div style='float: right;'>"
		if host['containment_state'] == "contained":
			x += "<a class='tableActionButton' id='uncontain_" + HXAPI.compat_str(host['_id']) + "'>uncontain</a>"
		elif (host['containment_state'] == "normal") and (host['containment_queued'] == False):
			x += "<a class='tableActionButton' id='contain_" + HXAPI.compat_str(host['_id']) + "'>contain</a>"
		elif (host['containment_state'] == "normal") and (host['containment_queued'] == True):
			x += "<a class='tableActionButton' id='appcontain_" + HXAPI.compat_str(host['_id']) + "'>approve</a>"
		x += "</div>"
		x += "</td>"
		
		import datetime
		t = HXAPI.gt(host['initial_agent_checkin'])
		x += "<td>" + HXAPI.prettyTime(t) + "</td>"
				
		x += "<td>" + HXAPI.compat_str(host['os']['product_name']) + " " + HXAPI.compat_str(host['os']['patch_level']) + " " + HXAPI.compat_str(host['os']['bitness']) + "</td>"
		x += "<td>" + HXAPI.compat_str(host['agent_version']) + "</td>"
		
		x += "<td>"
		x += "<a class='tableActionButton' id='triage_" + HXAPI.compat_str(host['_id']) + "'>triage</a>"
		x += "<a class='tableActionButton' id='fileaq_" + HXAPI.compat_str(host['_id']) + "'>file acq</a>"
		x += "<a class='tableActionButton' id='acq_" + HXAPI.compat_str(host['_id']) + "'>acquisition</a>"
		x += "</td>"
		
		x += "</tr>"
	
	x += "</table>"
	
	return (x)


def formatOpenIocs(iocs):

	x = "<select name='ioc' id='ioc'>"
	for entry in iocs:
			x += "<option value='" + entry['ioc_id'] + "'>" + entry['iocname']
	x += "</select>"
	return(x)


def formatScripts(scripts):

	x = "<select name='script' id='script'>"
	for entry in scripts:
			x += "<option value='" + entry['script_id'] + "'>" + entry['scriptname']
	x += "</select>"
	return(x)
