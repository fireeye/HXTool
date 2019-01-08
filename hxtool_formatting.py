
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

def formatCategoriesSelect(cats, setdefault="Custom"):

	x = "<select name='cats' id='cats'>"
	for entry in cats['data']['entries']:
		if entry['name'] == setdefault:
			x += "<option value='" + entry['uri_name'] + "' selected>" + entry['name']
		else:
			x += "<option value='" + entry['uri_name'] + "'>" + entry['name']
	x += "</select>"
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

