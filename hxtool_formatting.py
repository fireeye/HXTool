
from hxtool_config import *
from hx_lib import *
from hxtool_db import *
import time

def formatHostsets(hs):
	# The hidden/secret All Hosts host set
	x = "<option value='9'>All Hosts"
	
	for entry in hs['data']['entries']:
		x += "<option value='" + HXAPI.compat_str(entry['_id']) + "'>" + entry['name']
	
	return(x)

def formatHostsetsFabric(hs):

	x = '<li class="fe-dropdown__item">'
	x += '<a class="fe-dropdown__item-link">'
	x += '<span class="fe-dropdown__item-link-left-section">'
	x += '<i style="margin-top: 2px;" class="fas fa-object-group fa-lg"></i>'
	x += '</span>'
	x += '<span class="fe-dropdown__item-link-text" data-id="9">All hosts</span>'
	x += '<span class="fe-dropdown__item-link-right-section">'
	x += '<span style="color: black;" class="fe-badge count-only">9</span>'
	x += '</span></a></li>'

	for entry in hs['data']['entries']:
		x += '<li class="fe-dropdown__item">'
		x += '<a class="fe-dropdown__item-link">'
		x += '<span class="fe-dropdown__item-link-left-section">'
		x += '<i style="margin-top: 2px;" class="fas fa-object-group fa-lg"></i>'
		x += '</span>'
		x += '<span class="fe-dropdown__item-link-text" data-id="' + HXAPI.compat_str(entry['_id']) + '">' + entry['name'] + '</span>'
		x += '<span class="fe-dropdown__item-link-right-section">'
		x += '<span style="color: black;" class="fe-badge count-only">' + HXAPI.compat_str(entry['_id']) + '</span>'
		x += '</span></a></li>'

	return(x)


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
		bulk_download = ht_db.bulkDownloadGet(bulk_download_eid = job['bulk_download_eid'])
		x += "<tr>"
		x += "<td>" + HXAPI.compat_str(job.eid) + "</td>"
		x += "<td>" + HXAPI.compat_str(job['create_timestamp']) + "</td>"
		x += "<td>" + HXAPI.compat_str(job['update_timestamp']) + "</td>"
		x += "<td>" + job['stack_type'] + "</td>"
		x += "<td>" + ("STOPPED" if job['stopped'] else "RUNNING") + "</td>"
		x += "<td>" + HXAPI.compat_str(job['profile_id'])	+ "</td>"
		x += "<td>" + (HXAPI.compat_str(bulk_download['bulk_acquisition_id']) if 'bulk_acquisition_id' in bulk_download else "N/A") + "</td>"		
		x += "<td>" + HXAPI.compat_str(bulk_download['hostset_id']) + "</td>"
		
		# Completion rate
		job_progress = 0
		if 'hosts' in job:
			hosts_completed = len([_ for _ in job['hosts'] if _['processed']])
		else:
			hosts_completed = len([_ for _ in bulk_download['hosts'] if bulk_download['hosts'][_]['downloaded']])
		if hosts_completed > 0:
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

	
def formatOpenIocs(iocs):

	x = "<select name='ioc' id='ioc'>"
	for entry in iocs:
			x += "<option value='" + entry['ioc_id'] + "'>" + entry['iocname']
	x += "</select>"
	return(x)

def formatOpenIocsFabric(iocs):

	x = '';

	for entry in iocs:
		x += '<li class="fe-dropdown__item">'
		x += '<a class="fe-dropdown__item-link">'
		x += '<span class="fe-dropdown__item-link-left-section">'
		x += '<i style="margin-top: 2px;" class="fas fa-object-group fa-lg"></i>'
		x += '</span>'
		x += '<span class="fe-dropdown__item-link-text" data-id="' + HXAPI.compat_str(entry['ioc_id']) + '">' + entry['iocname'] + '</span>'
		x += '</a></li>'

	return(x)


def formatScripts(scripts):

	x = "<select name='script' id='script'>"
	for entry in scripts:
			x += "<option value='" + entry['script_id'] + "'>" + entry['scriptname']
	x += "</select>"
	return(x)


def formatScriptsFabric(scripts):

	x = ""
	for entry in scripts:
		x += '<li class="fe-dropdown__item">'
		x += '<a class="fe-dropdown__item-link">'
		x += '<span class="fe-dropdown__item-link-left-section">'
		x += '<i style="margin-top: 2px;" class="fas fa-code fa-lg"></i>'
		x += '</span>'
		x += '<span class="fe-dropdown__item-link-text" data-id="' + entry['script_id'] + '">' + entry['scriptname'] + '</span>'
		x += '<span class="fe-dropdown__item-link-right-section">'
		x += '</span></a></li>'
	return(x)

def formatTaskprofiles(mytaskprofiles):

	x = "<select name='taskprofile_id' id='taskprofile_id'>"
	for entry in mytaskprofiles:
			x += "<option value='" + entry['taskprofile_id'] + "'>" + entry['name']
	x += "</select>"
	return(x)


def formatTaskprofilesFabric(mytaskprofiles):

	x = ""
	x += '<li class="fe-dropdown__item">'
	x += '<a class="fe-dropdown__item-link">'
	x += '<span class="fe-dropdown__item-link-left-section">'
	x += '<i style="margin-top: 2px;" class="fas fa-object-group fa-lg"></i>'
	x += '</span>'
	x += '<span class="fe-dropdown__item-link-text" data-id="false">No profile</span>'
	x += '</a></li>'

	for entry in mytaskprofiles:
		x += '<li class="fe-dropdown__item">'
		x += '<a class="fe-dropdown__item-link">'
		x += '<span class="fe-dropdown__item-link-left-section">'
		x += '<i style="margin-top: 2px;" class="fas fa-object-group fa-lg"></i>'
		x += '</span>'
		x += '<span class="fe-dropdown__item-link-text" data-id="' + entry['taskprofile_id'] + '">' + entry['name'] + '</span>'
		x += '</a></li>'
	return(x)

