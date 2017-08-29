#!/usr/bin/env python
# -*- coding: utf-8 -*-

##########################
### HX REST functions
### Henrik Olsson @FireEye
##########################


try:
	import requests
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
	print("HXTool requires the 'requests' module, please install it.")
	exit(1)
	
import urllib
import base64
import json
import logging
import datetime
import pickle
import shutil


class HXAPI:
	HX_DEFAULT_PORT = 3000
	HX_MIN_API_VERSION = 2
	
	def __init__(self, hx_host, hx_port = HX_DEFAULT_PORT, headers = None, cookies = None, disable_certificate_verification = True, logger = logging.getLogger(__name__)):
		self.logger = logger

		self.logger.debug('__init__ start.')
		
		self.hx_host = hx_host
		self.logger.debug('hx_host set to %s.', self.hx_host)
		self.hx_port = hx_port
		self.logger.debug('hx_port set to %s.', self.hx_port)
		
		self._session = requests.Session()
		
		if headers:
			self.logger.debug('Appending additional headers passed to __init__')
			self._session.headers.update(headers)
		
		if cookies:
			self.logger.debug('Appending additional cookies passed to __init__')
			self._session.cookies.update(cookies)
		
		if disable_certificate_verification:
			self.logger.info('SSL/TLS certificate verification disabled.')
			self._session.verify = False
			requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		
		self.hx_user = None
		self.fe_token = None
		self.api_version = self.HX_MIN_API_VERSION
		self.hx_version = [0, 0, 0]
		
		
		self.logger.debug('__init__ complete.')
	
	
	###################
	## Generic functions
	###################
	
	# Mmmm, base64 flavored pickles...
	def serialize(self):
		return base64.b64encode(pickle.dumps(self, pickle.HIGHEST_PROTOCOL))
	
	@staticmethod
	def deserialize(base64_pickle):
		return pickle.loads(base64.b64decode(base64_pickle))
	
	# Loggers don't pickle nicely	
	def __getstate__(self):
		d = self.__dict__.copy()
		if 'logger' in d.keys():
			d['logger'] = d['logger'].name
		return d

	def __setstate__(self, d):
		if 'logger' in d.keys():
			d['logger'] = logging.getLogger(d['logger'])
		self.__dict__.update(d)	

	def build_request(self, url, method = 'GET', data = None, content_type = 'application/json', accept = 'application/json', auth = None):
	
		full_url = "https://{0}:{1}{2}".format(self.hx_host, self.hx_port, url)
		self.logger.debug('Full URL is: %s', full_url)
		
		self.logger.debug('Creating request.')
		request = requests.Request(method = method, url = full_url, data = data, auth = auth)
		self.logger.debug('HTTP method set to: %s', request.method)
		
		request.headers['Accept'] = accept
		self.logger.debug('Accept header set to: %s', accept)
		
		if method != 'GET' and method != 'DELETE':
			request.headers['Content-Type'] = content_type
			self.logger.debug('HTTP method is not GET or DELETE, Content-Type header set to: %s', content_type)
			
		self.logger.debug('Request created, returning.')
		return self._session.prepare_request(request)

	def build_api_route(self, api_endpoint, min_api_version = None):
		if not min_api_version:
			min_api_version = self.api_version
		return '/hx/api/v{0}/{1}'.format(min_api_version, api_endpoint)
		
	def handle_response(self, request, multiline_json = False, stream = False):
		
		response = None
		response_data = None
		
		try:
			response = self._session.send(request, stream = stream)

			if not response.ok:
				response.raise_for_status()

			content_type = response.headers.get('Content-Type')
			if content_type:
				if 'json' in content_type:
					if multiline_json:
						response_data = [json.loads(_) for _ in response.iter_lines(decode_unicode = True) if _.startswith(b'{')]
					else:
						response_data = response.json()
				elif 'text' in content_type:
					response_data = response.text
			else:
				response_data = response.content
					
			return(True, response.status_code, response_data, response.headers)	
		except (requests.HTTPError, requests.ConnectionError) as e:
			response_code = None
			if e.response:
				response_code = e.response.status_code
			return(False, response_code, e, None)
		
		

	def set_token(self, token):
		self.logger.debug('set_token called')
		
		timestamp = str(datetime.datetime.utcnow())
		if token:
			self.fe_token = {'token' : token, 'grant_timestamp' : timestamp, 'last_use_timestamp' : timestamp}
			# Add the token header to the requests Session
			self._session.headers['X-FeApi-Token'] = token
		else:
			self.fe_token = None
		
	def get_token(self, update_last_use_timestamp = True):
		self.logger.debug("get_token called, update_last_use_timestamp=%s", update_last_use_timestamp)
		
		if not self.fe_token:
			self.logger.debug("fe_token is empty.")
		elif update_last_use_timestamp:
			self.fe_token['last_use_timestamp'] = str(datetime.datetime.utcnow())

		return(self.fe_token)
	
	def _set_version(self):
		
		(ret, response_code, response_data) = self.restGetControllerVersion()
		if ret:
			version_string = response_data['data']['msoVersion']
			self.hx_version = [int(v) for v in version_string.split('.')]
			# TODO: this should be made into a dict
			if self.hx_version[0] == 2:
				self.api_version = 1
			elif self.hx_version[0] == 3:
				if self.hx_version[1] < 3:
					self.api_version = 2
				else:
					self.api_version = 3
	
	###################
	## Generic GET
	###################
	def restGetUrl(self, url, method = 'GET'):

		request = self.build_request(url, method = method)
		(ret, response_code, response_data, response_headers) = handle_response(request)
		
		return(ret, response_code, response_data)

	###################
	## Authentication
	###################

	# Authenticate and return X-FeApi-Token
	# A response code of 204 means that the
	# authentication request was sucessful.
	# A response code of 401 means that the
	# authentication request failed.
	# See page 47 in the API guide
	def restLogin(self, hx_api_username, hx_api_password):
	
		request = self.build_request(self.build_api_route('token', min_api_version = 1), auth = (hx_api_username, hx_api_password))

		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		if ret and response_code == 204:
			self.logger.debug('Token granted.')
			self.set_token(response_headers.get('X-FeApi-Token'))
			self.hx_user = hx_api_username
			self._set_version()
		
		return(ret, response_code, response_data)

	# Logout
	# 204 = Success
	# 304 = Failed due to missing API token
	# See page 746 of the API guide
	def restLogout(self):

		request = self.build_request(self.build_api_route('token', min_api_version = 1), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		self.logger.debug('Setting token to None.')
		self.set_token(None)
		
		return(ret, response_code, response_data)
		
	# Session expire after 15 minutes of inactivity
	# or 2.5 hours, whichever comes first.
	# See page 47 of the API guide
	def restIsSessionValid(self):
		
		current_token = self.get_token(update_last_use_timestamp=False)
		if current_token:
			last_use_delta = (datetime.datetime.utcnow() - datetime.datetime.strptime(current_token['last_use_timestamp'], '%Y-%m-%d %H:%M:%S.%f')).seconds / 60
			grant_time_delta = (datetime.datetime.utcnow() - datetime.datetime.strptime(current_token['grant_timestamp'], '%Y-%m-%d %H:%M:%S.%f')).seconds / 60
			return(last_use_delta < 15 and grant_time_delta < 150) 
		else:
			return(False)
			
			
	def restGetControllerVersion(self):

		request = self.build_request(self.build_api_route('version', min_api_version = 1))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	
	## Indicators
	#############

	# List indicator categories
	def restListIndicatorCategories(self):

		request = self.build_request(self.build_api_route('indicator_categories'))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# List all IOCs
	def restListIndicators(self, limit=10000):

		request = self.build_request(self.build_api_route('indicators?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	# Add a new condition
	def restAddCondition(self, ioc_category, ioc_guid, condition_class, condition_data):

		request = self.build_request(self.build_api_route('indicators/{0}/{1}/conditions/{2}'.format(ioc_category, ioc_guid, condition_class)), method = 'POST', data = condition_data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Add a new indicator
	def restAddIndicator(self, create_user, display_name, platforms, ioc_category):

		data = json.dumps({"create_text" : create_user, "display_name" : display_name, "platforms" : platforms})
		
		request = self.build_request(self.build_api_route('indicators/{0}'.format(ioc_category)), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Submit a new category
	def restCreateCategory(self, category_name):

		request = self.build_request(self.build_api_route('indicator_categories/{0}'.format(category_name)), method = 'PUT', data = '{}')
		request.add_header('If-None-Match', '*')
		
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Grab conditions from an indicator
	def restGetCondition(self, ioc_category, ioc_uri, condition_class, limit=10000):

		request = self.build_request(self.build_api_route('indicators/{0}/{1}/conditions/{2}?limit={3}'.format(ioc_category, ioc_uri, condition_class, limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# List all indicators
	def restListIndicators(self, limit=10000):

		request = self.build_request(self.build_api_route('indicators?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Get indicator based on condition
	def restGetIndicatorFromCondition(self, condition_id):

		request = self.build_request(self.build_api_route('conditions/{0}/indicators'.format(condition_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Delete an indicator by name
	def restDeleteIndicator(self, ioc_category, ioc_name):
		
		request = self.build_request(self.build_api_route('indicators/{0}/{1}'.format(ioc_category, ioc_name)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restGetConditionDetails(self, condition_id):
	
		request = self.build_request(self.build_api_route('conditions/{0}'.format(condition_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	

	## Acquisitions
	###############

	# Acquire triage
	def restAcquireTriage(self, agent_id, timestamp = False):

		data = '{}'
		if timestamp:
			data = json.dumps({'req_timestamp' : timestamp})
			
		request = self.build_request(self.build_api_route('hosts/{0}/triages'.format(agent_id)), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Acquire file
	def restAcquireFile(self, agent_id, path, filename, mode = True):

		# Mode = True = API mode
		# Mode = False = RAW mode
	
		data = json.dumps({'req_path' : path, 'req_filename' : filename, 'req_use_api' : mode})
		
		request = self.build_request(self.build_api_route('hosts/{0}/files'.format(agent_id)), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restNewAcquisition(self, agent_id, scriptname, script):

		data = json.dumps({'name' : scriptname, 'script' : {'b64' : base64.b64encode(script)}})
		
		request = self.build_request(self.build_api_route('hosts/{0}/live'.format(agent_id)), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# List Bulk Acquisitions
	def restListBulkAcquisitions(self, limit=10000):

		request = self.build_request(self.build_api_route('acqs/bulk?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		return(ret, response_code, response_data)


	# List hosts in Bulk acquisition
	def restListBulkHosts(self, bulk_id, limit=10000):

		request = self.build_request(self.build_api_route('acqs/bulk/{0}/hosts?limit={1}'.format(bulk_id, limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Get the status of a bulk acquisition for a single host	
	def restGetBulkHost(self, bulk_id, host_id):

		request = self.build_request(self.build_api_route('acqs/bulk/{0}/hosts/{1}'.format(bulk_id, host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# Get Bulk acquistion detail
	def restGetBulkDetails(self, bulk_id):

		request = self.build_request(self.build_api_route('acqs/bulk/{0}'.format(bulk_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	# Download bulk data
	def restDownloadFile(self, url, destination_file_path = None):

		request = self.build_request(url, accept = 'application/octet-stream')
		try:
			response = self._session.send(request, stream = True)
			
			if destination_file_path: 
				with open(destination_file_path, 'wb') as f:
					shutil.copyfileobj(response.raw, f)
				return(True, response.status_code, None)	
			else:
				return(True, response.status_code, response.raw)
				
		except (requests.HTTPError, requests.ConnectionError) as e:
			response_code = None
			if e.response:
				response_code = e.response.status_code
			return(False, response_code, e)
			
	# Delete bulk acquisition file		
	def restDeleteFile(self, url):
		
		request = self.build_request(self.build_api_route(url), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# New Bulk acquisition
	def restNewBulkAcq(self, script, hostset_id = None, hosts = None, comment = None, platforms = '*'):
		
		script = base64.b64encode(script).decode('ascii')
	
		data = {'scripts' : [{'platform' : platforms, 'b64' : script}]}
		if hostset_id:
			data['host_set'] = {'_id' : hostset_id}
		elif hosts:
			data['hosts'] = hosts
			
		if comment:
			data['comment'] = comment
	
		request = self.build_request(self.build_api_route('acqs/bulk'), method = 'POST', data = json.dumps(data))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# List normal acquisitions
	def restListAcquisitions(self):

		request = self.build_request(self.build_api_route('acqs'))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restListFileAcquisitionsHost(self, host_id):

		request = self.build_request(self.build_api_route('hosts/{0}/files'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restListTriageAcquisitionsHost(self, host_id):

		request = self.build_request(self.build_api_route('hosts/{0}/triages'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restListDataAcquisitionsHost(self, host_id):

		request = self.build_request(self.build_api_route('hosts/{0}/live'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

		
	# List file acquisitions
	def restListFileaq(self, limit=10000):

		request = self.build_request(self.build_api_route('acqs/files?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restListTriages(self, limit=10000):

		request = self.build_request(self.build_api_route('acqs/triages?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	#######################
	## Enterprise Search ##
	#######################

	def restListSearches(self):

		request = self.build_request(self.build_api_route('searches'))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	def restSubmitSweep(self, indicator, host_set):
		
		indicator = base64.b64encode(indicator).decode('ascii')
		
		data = json.dumps({'indicator' : indicator, 'host_set' : {'_id' : int(host_set)}})
		
		request = self.build_request(self.build_api_route('searches'), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restCancelJob(self, path, id):

		request = self.build_request(self.build_api_route('{0}/{1}/actions/stop'.format(path, id)), method = 'POST')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restDeleteJob(self, path, id):

		request = self.build_request(self.build_api_route('{0}/{1}'.format(path, id)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restGetSearchHosts(self, search_id):

		request = self.build_request(self.build_api_route('searches/{0}/hosts?errors=true'.format(search_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restGetSearchResults(self, search_id):

		request = self.build_request(self.build_api_route('searches/{0}/results'.format(search_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	##########
	# Alerts #
	##########

	def restGetAlertID(self, alert_id):

		request = self.build_request(self.build_api_route('alerts/{0}'.format(alert_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restGetAlerts(self, limit):

		request = self.build_request(self.build_api_route('alerts?sort=reported_at+desc&limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# NOTE: this function does not return data in the usual way, the response is a list of alerts
	def restGetAlertsHost(self, agent_id):
	
		data = json.dumps({'agent._id' : [agent_id]})
	
		request = self.build_request(self.build_api_route('alerts/filter'), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request, multiline_json = True)
		
		if ret:
			from operator import itemgetter
			sorted_alert_list = sorted(response_data, key=itemgetter('reported_at'), reverse=True);
			return(True, response_code, sorted_alert_list)
		
		else:
			return(ret, response_code, response_data)
		
	# NOTE: this function does not return data in the usual way, the response is a list of alerts
	def restGetAlertsTime(self, start_date, end_date):

		data = json.dumps({'event_at' : 
							{'min' : '{0}T00:00:00.000Z'.format(start_date), 
							'max' : '{0}T23:59:59.999Z'.format(end_date)}
						})
							
		request = self.build_request(self.build_api_route('alerts/filter'), method = 'POST', data = data)
		
		(ret, response_code, response_data, response_headers) = self.handle_response(request, multiline_json = True)
		
		if ret:
			from operator import itemgetter
			sorted_alert_list = sorted(response_data, key=itemgetter('reported_at'), reverse=True);
			return(True, response_code, sorted_alert_list)
		
		else:
			return(ret, response_code, response_data)
			


	########
	# Hosts
	########
		
	def restListHosts(self, limit=100000):

		request = self.build_request(self.build_api_route('hosts?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restDeleteHostByID(self, agent_id):
		
		request = self.build_request(self.build_api_route('hosts/{0}'.format(agent_id)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restFindHostsBySearchString(self, search_string, limit = 1000):
	
		request = self.build_request(self.build_api_route('hosts?limit={0}&search={1}'.format(limit, urllib.quote_plus(search_string))))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restGetHostSummary(self, host_id):

		request = self.build_request(self.build_api_route('hosts/{0}'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restGetHostSysinfo(self, host_id):

		request = self.build_request(self.build_api_route('hosts/{0}/sysinfo'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	def restGetContainmentStatus(self, host_id):
	
		request = self.build_request(self.build_api_route('hosts/{0}/containment'.format(host_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	def restRequestContainment(self, host_id):
	
		request = self.build_request(self.build_api_route('hosts/{0}/containment'.format(host_id)), method = 'POST')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restApproveContainment(self, host_id):
	
		data = json.dumps({'state' : 'contain'})
	
		request = self.build_request(self.build_api_route('hosts/{0}/containment'.format(host_id)), method = 'PATCH', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restRemoveContainment(self, host_id):
	
		request = self.build_request(self.build_api_route('hosts/{0}/containment'.format(host_id)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	###########
	# Host Sets
	###########
		
	def restListHostsets(self, limit=100000):

		request = self.build_request(self.build_api_route('host_sets?limit=100000'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restListHostsInHostset(self, host_set_id):

		request = self.build_request(self.build_api_route('host_sets/{0}/hosts'.format(host_set_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	##################
	# Config Channels
	##################	
		
	def restCheckAccessCustomConfig(self, limit=1):

		request = self.build_request(self.build_api_route('host_policies/channels?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
			
	def restListCustomConfigChannels(self, limit=1000):

		request = self.build_request(self.build_api_route('host_policies/channels?limit={0}'.format(limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	def restNewConfigChannel(self, name, description, priority, host_sets, conf):

		myhostsets = []
		for hs in host_sets:
			myhostsets.append({"_id": int(hs)})
		
		try:
			myconf = json.loads(conf)
		except ValueError:
			print("Failed to parse incoming json")
			print(conf)
		
		data = json.dumps({'name' : name, 'description' : description, 'priority' : int(priority), 'host_sets' : myhostsets, 'configuration' : myconf})
		
		request = self.build_request(self.build_api_route('host_policies/channels'), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	def restGetConfigChannel(self, channel_id):
		
		request = self.build_request(self.build_api_route('host_policies/channels/{0}'.format(channel_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restGetConfigChannelConfiguration(self, channel_id):
		
		request = self.build_request(self.build_api_route('host_policies/channels/{0}.json'.format(channel_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)	
	
	def restDeleteConfigChannel(self, channel_id):

		request = self.build_request(self.build_api_route('host_policies/channels/{0}'.format(channel_id)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
			
	####
	# Generic functions
	####
	@staticmethod
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

	@staticmethod	
	def gt(dt_str):
		
		dt, _, us= dt_str.partition(".")
		dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
		us = int(us.rstrip("Z"), 10)
		return dt + datetime.timedelta(microseconds=us)
		

			
		
