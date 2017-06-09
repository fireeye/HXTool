##########################
### HX REST functions
### Henrik Olsson @FireEye
##########################

import urllib2
import urllib
import base64
import json
import ssl


###################
## Generic functions
###################

def restBuildRequest(hxip, hxport, url, method = 'GET', data = None, fetoken = None, content_type = 'application/json', accept = 'application/json', headers = None, cookies = None):

	if hasattr(ssl, '_create_unverified_context'):
		ssl._create_default_https_context = ssl._create_unverified_context

	opener = urllib2.build_opener(urllib2.HTTPSHandler)
	urllib2.install_opener(opener)

	if headers:
		request = urllib2.Request("https://{0}:{1}{2}".format(hxip, hxport, url), data = data, headers = headers)
	else:
		request = urllib2.Request("https://{0}:{1}{2}".format(hxip, hxport, url), data = data)
	
	# XFIRE_HMAC_SESSION cookie for use with Crossfire. First login to CrossFire from a browser and copy this cookie value
	# Should be moved to config(conf.json)
	#cookies = {'XFIRE_HMAC_SESSION' : '<change me!>'}
	
	request.get_method = lambda: method
	request.add_header('Accept', accept)
	request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT; rv:53.0) Gecko/20100101 Firefox/53.0')
	if method != 'GET' or method != 'DELETE':
		request.add_header('Content-Type', content_type)
	if fetoken:
		request.add_header('X-FeApi-Token', fetoken)
	if cookies and len(cookies) > 0:
		request.add_header('Cookie', ';'.join('='.join(_) for _ in cookies.items()) + ';')
	
	return request

def restGetUrl(url, fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, url, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
	
	return(r)


###################
## Authentication
###################

# Authenticate and return X-FeApi-Token
def restValidateAuth(hxip, hxport, hxuser, hxpass):

	upstring = base64.b64encode(hxuser + ':' + hxpass)

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/token', headers = {'Authorization' : 'Basic {0}'.format(upstring)})

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		msg = e.read()
		return(False, msg)
	except urllib2.URLError as e:
		msg = e.reason
		return(False, msg)
	else:
		fetoken = (response.info().getheader('X-FeApi-Token'))
		return(True, fetoken)


# Logout
def restLogout(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/token', method = 'DELETE', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		return()

def restIsSessionValid(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/version', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
		return True
	except:
		return False


################
## Resolve hosts
################

def restFindHostbyString(string, fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/hosts?search={0}'.format(urllib.urlencode(string)), fetoken = fetoken, data = '{}')

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


## Indicators
#############

# List indicator categories
def restListIndicatorCategories(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/indicator_categories', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		categories = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(categories)

# List all IOCs
def restListIndicators(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/indicators?limit=10000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		iocs = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(iocs)


# Add a new condition
def restAddCondition(iocURI, ioctype, data, cat, fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/indicators/{0}/{1}/conditions/{2}'.format(cat, iocURI, ioctype), method = 'POST', data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(res)

# Add a new indicator
def restAddIndicator(cuser, name, category, platforms, fetoken, hxip, hxport):

	data = json.dumps({"create_text" : cuser, "display_name" : name, "platforms" : platforms})
	request = restBuildRequest(hxip, hxport, '/hx/api/v3/indicators/{0}'.format(category), method = 'POST', data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		iocURI = r['data']['uri_name']
		return(iocURI)

# Submit a new category
def restCreateCategory(fetoken, catname, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/indicator_categories/{0}'.format(catname), method = 'PUT', data = '{}', fetoken = fetoken, headers = {'If-None-Match', '*'})

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(res)

# Grab conditions from an indicator
def restGetCondition(fetoken, ioctype, category, iocuri, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/indicators/{0}/{1}/conditions/{2}?limit=10000'.format(category, iocuri, ioctype), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		resp_cond = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(resp_cond)

# List all indicators
def restListIndicators(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/indicators?limit=10000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

# Get indicator based on condition
def restGetIndicatorFromCondition(fetoken, conditionid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/conditions/{0}/indicators'.format(conditionid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)



## Acquisitions
###############

# Acquire triage
def restAcquireTriage(agentId, fetoken, hxip, hxport, timestamp = False):

	data = '{}'
	if timestamp:
		data = json.dumps({'req_timestamp' : timestamp})

	request = restBuildRequest(hxip, hxport, '/hx/api/v1/hosts/{0}/triages'.format(agentId), data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

# Acquire file
def restAcquireFile(agentId, fetoken, path, filename, mode, hxip, hxport):

	newpath = path.replace('\\','\\\\')
	data = json.dumps({'req_path' : newpath, 'req_filename' : filename, 'req_use_api' : str(mode != "RAW").lower()})
	request = restBuildRequest(hxip, hxport, '/hx/api/v1/hosts/{0}/files'.format(agentId), method = 'POST', data = data, fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

# List Bulk Acquisitions
def restListBulkAcquisitions(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/bulk?limit=1000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


# List hosts in Bulk acquisition
def restListBulkDetails(fetoken, bulkid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/bulk/{0}/hosts?limit=100000'.format(bulkid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


# Get Bulk acquistion detail
def restGetBulkDetails(fetoken, bulkid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/bulk/{0}'.format(bulkid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


# Download bulk data
def restDownloadBulkAcq(fetoken, url, hxip, hxport):

	request = restBuildRequest(hxip, hxport, url, accept = 'application/octet-stream', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		return(response.read())


# New Bulk acquisition

def restNewBulkAcq(fetoken, script, hostset, hxip, hxport):

	data = json.dumps({'host_set' : {'_id' : int(hostset)}, 'script' : {'b64' : base64.b64encode(script)}})
	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/bulk', method = 'POST', data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


# List normal acquisitions
def restListAcquisitions(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

# List file acquisitions
def restListFileaq(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/files?limit=10000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restListTriages(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/acqs/triages?limit=10000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


#######################
## Enterprise Search ##
#######################

def restListSearches(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/searches', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


def restSubmitSweep(fetoken, hxip, hxport, b64ioc, hostset):

	data = json.dumps({'indicator' : b64ioc, 'host_set' : {'_id' : int(hostset)}})
	request = restBuildRequest(hxip, hxport, '/hx/api/v2/searches', method = 'POST', data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restCancelJob(fetoken, id, path, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '{0}{2}/actions/stop'.format(path, id), method = 'POST', fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restDeleteJob(fetoken, id, path, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '{0}{1}'.format(path, id), method = 'DELETE', fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		#r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return()

def restGetSearchHosts(fetoken, searchid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/searches/{0}/hosts?errors=true'.format(searchid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)



def restGetSearchResults(fetoken, searchid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/searches/{0}/results'.format(searchid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


##########
# Alerts #
##########

def restGetAlertID(fetoken, alertid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/alerts/{0}'.format(alertid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restGetAlerts(fetoken, count, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/alerts?sort=reported_at+desc&limit={0}'.format(count), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


# NOTE: this function does not return data in the usual way, the response is a list of alerts
def restGetAlertsTime(fetoken, startdate, enddate, hxip, hxport):

	data = json.dumps({'event_at' : 
						{'min' : '{0}T00:00:00.000Z'.format(startdate), 
						'max' : '{0}T23:59:59.999Z'.format(enddate)}
					})
						
	request = restBuildRequest(hxip, hxport, '/hx/api/v3/alerts/filter', method = 'POST', data = data, fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = [];
		for line in response.read().decode(response.info().getparam('charset') or 'utf-8').split('\n'):
			if line.startswith('{'):
				r.append(json.loads(line))
		
		from operator import itemgetter
		newlist = sorted(r, key=itemgetter('reported_at'), reverse=True)
		return(newlist)


##############
# Query host
##############

def restGetHostSummary(fetoken, hostid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/hosts/{0}'.format(hostid), fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)



########
# Hosts
########

def restListHosts(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/hosts?limit=100000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)


def restListHostsets(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v2/host_sets?limit=100000', fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restCheckAccessCustomConfig(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/host_policies/channels?limit=1', fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		return(False)
	except urllib2.URLError as e:
		return(False)
	else:
		return(True)
		
def restListCustomConfigChannels(fetoken, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/host_policies/channels?limit=1000', fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

		
def restNewConfigChannel(fetoken, name, description, priority, hostset, conf, hxip, hxport):

	myhostsets = []
	for hs in hostset:
		myhostsets.append({"_id": int(hs)})
	
	try:
		myconf = json.loads(conf)
	except ValueError:
		print "Failed to parse incoming json"
		print conf
	
	data = json.dumps({'name' : name, 'description' : description, 'priority' : int(priority), 'host_sets' : myhostsets, 'configuration' : myconf})
	request = restBuildRequest(hxip, hxport, '/hx/api/v3/host_policies/channels', method = 'POST', data = data, fetoken = fetoken)

	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		r = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		return(r)

def restDeleteConfigChannel(fetoken, channelid, hxip, hxport):

	request = restBuildRequest(hxip, hxport, '/hx/api/v3/host_policies/channels/' + channelid, method = 'DELETE', fetoken = fetoken)
	
	try:
		response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
		print e.read()
	except urllib2.URLError as e:
		print 'Failed to connect to HX API server.'
		print 'Reason: ', e.reason
	else:
		return
	
		
####
# Generic functions
####

def prettyTime(time=False):
	
	from datetime import datetime

	now = datetime.utcnow()
	if type(time) is int:
		diff = now - datetime.fromtimestamp(time)
	elif isinstance(time,datetime):
		diff = now - time
	elif not time:
		diff = now - now

	second_diff = diff.seconds
	day_diff = diff.days

	if day_diff < 0:
		return ''

	if day_diff == 0:
		if second_diff < 10:
			return "just now"
		if second_diff < 60:
			return str(second_diff) + " seconds ago"
		if second_diff < 120:
			return "a minute ago"
		if second_diff < 3600:
			return str(second_diff / 60) + " minutes ago"
		if second_diff < 7200:
			return "an hour ago"
		if second_diff < 86400:
			return str(second_diff / 3600) + " hours ago"
	if day_diff == 1:
		return "Yesterday"
	if day_diff < 7:
		return str(day_diff) + " days ago"
	if day_diff < 31:
		return str(day_diff / 7) + " weeks ago"
	if day_diff < 365:
		return str(day_diff / 30) + " months ago"
	
	return str(day_diff / 365) + " years ago"

def gt(dt_str):
	
	import datetime
	dt, _, us= dt_str.partition(".")
	dt= datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
	us= int(us.rstrip("Z"), 10)
	return dt + datetime.timedelta(microseconds=us)
