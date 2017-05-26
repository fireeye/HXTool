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

###################
## Generic functions
###################
	
def restGetUrl(url, fetoken, hxip, hxport):
	
	handler = urllib2.HTTPHandler()
	opener = urllib2.build_opener(handler)
	urllib2.install_opener(opener)
	data = None
	
	request = urllib2.Request('https://' + hxip + ':' + hxport + url, data=data)
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
	
	
###################
## Authentication
###################

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

		
################
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
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/indicators?limit=10000', data=data)
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
def restAddIndicator(cuser, name, category, platforms, fetoken, hxip, hxport):
			
        data = json.dumps({"create_text" : cuser, "display_name" : name, "platforms" : platforms})
		
        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/indicators/' + category, data=data)
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
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/indicators?limit=10000', data=data)

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

	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/bulk?limit=1000', data=data)
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
	request = urllib2.Request('https://' + str(hxip) + ':' + hxport + '/hx/api/v2/acqs/bulk/' +  str(bulkid) + '/hosts?limit=100000', data=data)

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

        data = None

        request = urllib2.Request('https://' + str(hxip) + ':' + hxport + '/hx/api/v2/acqs/bulk/' +  str(bulkid), data=data)

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

        data = """{"host_set":{"_id":""" + str(hostset) +  """},"script":{"b64":""" + sc + """}}"""

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

		
# List normal acquisitions
def restListAcquisitions(fetoken, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = None

	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs', data=data)
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

# List file acquisitions
def restListFileaq(fetoken, hxip, hxport):

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/files?limit=10000', data=data)
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

def restListTriages(fetoken, hxip, hxport):

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/acqs/triages?limit=10000', data=data)
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


def restSubmitSweep(fetoken, hxip, hxport, b64ioc, hostset):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

	data = """{"indicator":""" + "\"" + b64ioc + "\"" + ""","host_set":{"_id":""" + hostset + """}}"""
	
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

def restCancelJob(fetoken, id, path, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + str(hxip) + ':' + hxport + path + str(id) + '/actions/stop', data=data)
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

def restDeleteJob(fetoken, id, path, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + str(hxip) + ':' + hxport + path + str(id), data=data)
        request.add_header('X-FeApi-Token', fetoken)
        request.add_header('Accept', 'application/json')
        #request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'DELETE'

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

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/searches/' + searchid + "/results", data=data)
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

def restGetAlertID(fetoken, alertid, hxip, hxport):

	data = None
	
	request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/alerts/' + alertid, data=data)
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

def restGetAlerts(fetoken, count, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/alerts?sort=reported_at+desc&limit=' + count, data=data)
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

				
# NOTE: this function does not return data in the usual way, the response is a list of alerts
def restGetAlertsTime(fetoken, startdate, enddate, hxip, hxport):

		handler = urllib2.HTTPHandler()
		opener = urllib2.build_opener(handler)
		urllib2.install_opener(opener)

		data = """{"event_at":{"min":""" + "\"" + startdate + """T00:00:00.000Z","max":""" + "\"" + enddate + """T23:59:59.999Z"}}"""
        
		request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v3/alerts/filter', data=data)
		request.add_header('X-FeApi-Token', fetoken)
		request.add_header('Accept', 'application/json')
		request.add_header('Content-type', 'application/json')
		request.get_method = lambda: 'POST'

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

				
def restListHostsets(fetoken, hxip, hxport):

        handler = urllib2.HTTPHandler()
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)

        data = None

        request = urllib2.Request('https://' + hxip + ':' + hxport + '/hx/api/v2/host_sets?limit=100000', data=data)
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