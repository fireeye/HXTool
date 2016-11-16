##########################
### HX REST functions
### Henrik Olsson @FireEye
##########################

import urllib2
import base64
import json
import ssl

if hasattr(ssl, '_create_unverified_context'):
        ssl._create_default_https_context = ssl._create_unverified_context

# Authenticate and return X-FeApi-Token
def restAuth(hxip, hxport, hxuser, hxpass):

        upstring = base64.b64encode(hxuser + ':' + hxpass)

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)
        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/token', data=data)
        request.add_header('Accept', 'application/json')
        request.add_header('Authorization', 'Basic ' + upstring)
        request.get_method = lambda: 'GET'

        try:
                response = urllib2.urlopen(request)
        except urllib2.HTTPError as e:
                print e.read()
        except urllib2.URLError as e:
                print 'Failed to connect to HX API server.'
                print 'Reason: ', e.reason
        else:
                fetoken = (response.info().getheader('X-FeApi-Token'))
                return(fetoken)

def restValidateAuth(hxip, hxport, hxuser, hxpass):

        upstring = base64.b64encode(hxuser + ':' + hxpass)

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)
        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/token', data=data)
        request.add_header('Accept', 'application/json')
        request.add_header('Authorization', 'Basic ' + upstring)
        request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)
        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/token', data=data)
        request.add_header('Accept', 'application/json')
	request.add_header('X-FeApi-Token',fetoken)
        request.get_method = lambda: 'DELETE'

        try:
                response = urllib2.urlopen(request)
        except urllib2.HTTPError as e:
                print e.read()
        except urllib2.URLError as e:
                print 'Failed to connect to HX API server.'
                print 'Reason: ', e.reason
        else:
                return()


## Resolve hosts
################

def restFindHostbyString(string, fetoken, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)
        data = """{}"""

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/hosts?search=' + string, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

        data = None
        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicator_categories', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

	data = None
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicators?limit=10000', data=data)
	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/json')
	request.get_method = lambda: 'GET'

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
        ioctype_path = "/conditions/" + ioctype

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicators/' + cat + '/' + iocURI + ioctype_path, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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
def restAddIndicator(cuser, name, category, fetoken, hxip, hxport):

        data = "{\"create_text\":\"" + cuser + "\",\"display_name\":\"" + name + "\"}"
        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicators/' + category, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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

        data = """{}"""

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicator_categories/' + catname, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.add_header('If-None-Match', '*')
        request.get_method = lambda: 'PUT'

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

	data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/indicators/' + category + '/' + iocuri + '/conditions/' + ioctype + '?limit=10000', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

	handler = urllib2.HTTPHandler()
	opener = urllib2.build_opener(handler)
	urllib2.install_opener(opener)

	data = None
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/indicators?limit=10000', data=data)

	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/json')
	request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None
        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/conditions/' + conditionid + '/indicators', data=data)

        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

        if timestamp:
                data = "{\"req_timestamp\": \"" + timestamp + "\"}"
        else:
                data = """{}"""

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/hosts/' + agentId + '/triages', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        newpath = path.replace('\\','\\\\')

        if (mode == "RAW"):
                data = "{\"req_path\":\"" + newpath + "\",\"req_filename\":\"" + filename + "\"}"
        else:
                data = "{\"req_path\":\"" + newpath + "\",\"req_filename\":\"" + filename + "\",\"req_use_api\":true}"

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v1/hosts/' + agentId + '/files', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = None

	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/bulk', data=data)
	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/json')
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = None
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/bulk/' +  bulkid + '/hosts', data=data)

	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/json')
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/bulk/' +  bulkid, data=data)

	request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = None
	request = urllib2.Request('https://' + hxip + ':' + hxport + url, data=data)
	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/octet-stream')
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        sc = base64.b64encode(script)
        sc = "\"" + sc + "\""

        data = """{"host_set":{"_id":""" + hostset +  """},"script":{"b64":""" + sc + """}}"""

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/bulk', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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

	handler = urllib2.HTTPHandler()
	opener = urllib2.build_opener(handler)
	urllib2.install_opener(opener)

	data = None
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/searches', data=data)
	request.add_header('X-FeApi-Token', fetoken)
	request.add_header('Accept', 'application/json')
	request.get_method = lambda: 'GET'
	
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


def restSubmitSweep(fetoken, hxip, hxport, b64ioc):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = """{"indicator":""" + "\"" + b64ioc + "\"" + ""","host_set":{"_id":1010}}"""

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/searches', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
	request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'POST'

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


def restGetSearchHosts(fetoken, searchid, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/searches/' + searchid + '/hosts?errors=true', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/searches/' + searchid + '/results', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

def restGetAlerts(fetoken, count, hxip, hxport):


        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/alerts?limit=' + count, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

##############
# Query host
##############

def restGetHostSummary(fetoken, hostid, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/hosts/' + hostid, data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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



def restIsSessionValid(fetoken, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/version', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

	try:
		response = urllib2.urlopen(request)
		return True
	except:
		return False	

########
# Hosts
########

def restListHosts(fetoken, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/hosts?limit=100000', data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        request.get_method = lambda: 'GET'

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

