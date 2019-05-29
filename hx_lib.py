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
	DEFAULT_LIMIT = 100000
	
	def __init__(self, hx_host, hx_port = HX_DEFAULT_PORT, headers = None, cookies = None, proxies = None, disable_certificate_verification = True, logger_name = None, default_encoding = 'utf-8'):
		if logger_name:
			self.logger = logging.getLogger(logger_name)
		else:
			self.logger = logging.getLogger(__name__)
		
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
			self.suppress_requests_insecure_warning()
		
		if proxies:
			self._session.proxies = proxies
			self.logger.info("Proxy support enabled.")
		
		self.hx_user = None
		self._hx_password = None
		self.auto_renew_token = False
		self.fe_token = None
		self.api_version = self.HX_MIN_API_VERSION
		self.hx_version = [0, 0, 0]
		
		self.default_encoding = default_encoding
		self.logger.debug('Encoding set to: %s.', self.default_encoding)
		
		self.logger.debug('__init__ complete.')
	
	###################
	## Generic functions
	###################
	
	# Mmmm, base64 flavored pickles...
	def serialize(self):
		return HXAPI.b64(pickle.dumps(self, pickle.HIGHEST_PROTOCOL))
	
	@staticmethod
	def deserialize(base64_pickle):
		return pickle.loads(HXAPI.b64(base64_pickle, True))
	
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
		if not self._session.verify:
			self.suppress_requests_insecure_warning()	

	def suppress_requests_insecure_warning(self):
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		
	def build_request(self, url, method = 'GET', params = None, data = None, content_type = 'application/json', accept = 'application/json', auth = None):
	
		full_url = "https://{0}:{1}{2}".format(self.hx_host, self.hx_port, url)
		
		self.logger.debug('Creating request.')
		request = requests.Request(method = method, url = full_url, params = params, data = data, auth = auth)
		self.logger.debug('HTTP method set to: %s', request.method)
		
		request.headers['Accept'] = accept
		self.logger.debug('Accept header set to: %s', accept)
		
		if method != 'GET' and method != 'DELETE':
			request.headers['Content-Type'] = content_type
			self.logger.debug('HTTP method is not GET or DELETE, Content-Type header set to: %s', content_type)
		
		# Set the token here, this ensures the last_use_timestamp is properly updated on each request
		api_token = self.get_token()
		if api_token:
			self.logger.debug("Setting X-FeApi-Token header")
			self._session.headers['X-FeApi-Token'] = api_token['token']
		
		pr = self._session.prepare_request(request)
		
		self.logger.debug('Full URL is: %s', pr.url)
		
		self.logger.debug('Request created, returning.')
		return pr

	def build_api_route(self, api_endpoint, min_api_version = None):
		if not min_api_version:
			min_api_version = self.api_version
		return '/hx/api/v{0}/{1}'.format(min_api_version, api_endpoint)
		
	def handle_response(self, request, multiline_json = False, multiline_json_limit = DEFAULT_LIMIT, stream = False):
		
		response = None
		response_data = None
		
		try:
			with self._session.send(request, stream = stream) as response:

				if not response.ok:
					response.raise_for_status()
				
				if not response.encoding:
					response.encoding = self.default_encoding
			
				# The HX API documentations states that the controller will include a new
				# token in the response when the existing token is nearing expiration.
				if 'X-FeApi-Token' in response.headers:
					self.set_token(response.headers.get('X-FeApi-Token'))
			
				content_type = response.headers.get('Content-Type', None)
				if content_type is not None and 'json' in content_type.lower():
					if multiline_json:
						line_count = 0
						response_data = []
						for l in response.iter_lines(decode_unicode = True):
							if l.startswith('{'):
								response_data.append(json.loads(l))
								line_count += 1
							if line_count >= multiline_json_limit:
								break
					else:
						response_data = response.json()
				else:
					response_data = response.text
					if response_data.startswith('{'):
						self.logger.info("Possible JSON in response without corresponding Content-Type header.")
						
				return(True, response.status_code, response_data, response.headers)	
		except (requests.exceptions.ChunkedEncodingError, requests.HTTPError, requests.ConnectionError) as e:
			if hasattr(e, 'response') and e.response is not None:
				response = e.response
			
				# Check if error message is content type JSON
				content_type = response.headers.get('Content-Type', None)
				if content_type is not None and 'json' in content_type.lower():
					response_data = response.json()
				else:
					response_data = response.text

				return(False, response.status_code, response_data, response.headers)
			return(False, None, e, None)
		
		

	def set_token(self, token):
		self.logger.debug('set_token called')
		
		timestamp = HXAPI.dt_to_str(datetime.datetime.utcnow())
		if token:
			self.fe_token = {'token' : token, 'grant_timestamp' : timestamp, 'last_use_timestamp' : timestamp}
			# Removed the code setting the X-FeApi-Token header from here because the last_use_timestamp would never get updated
		else:
			self.fe_token = None
		
	def get_token(self, update_last_use_timestamp = True):
		self.logger.debug("get_token called, update_last_use_timestamp=%s", update_last_use_timestamp)
		
		if not self.fe_token:
			self.logger.debug("fe_token is empty.")
		elif update_last_use_timestamp:
			self.fe_token['last_use_timestamp'] = HXAPI.dt_to_str(datetime.datetime.utcnow())

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
			elif self.hx_version[0] == 4:
				self.api_version = 3
	
	###################
	## Generic GET
	###################
	def restGetUrl(self, url, method = 'GET'):

		request = self.build_request(url, method = method)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
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
	def restLogin(self, hx_api_username, hx_api_password, auto_renew_token = False):
	
		request = self.build_request(self.build_api_route('token', min_api_version = 1), auth = (hx_api_username, hx_api_password))

		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		if ret and response_code == 204 and 'X-FeApi-Token' in response_headers:
			self.logger.debug('Token granted.')
			self.set_token(response_headers.get('X-FeApi-Token'))
			self.hx_user = hx_api_username
			self.auto_renew_token = auto_renew_token
			if self.auto_renew_token:
				self._hx_password = hx_api_password
			self._set_version()
		else:
			ret = False
		
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
		is_valid = False
		current_token = self.get_token(update_last_use_timestamp=False)
		if current_token:
			last_use_delta = (datetime.datetime.utcnow() - HXAPI.dt_from_str(current_token['grant_timestamp'])).seconds / 60
			grant_time_delta = (datetime.datetime.utcnow() - HXAPI.dt_from_str(current_token['grant_timestamp'])).seconds / 60
			self.logger.debug("Token last_use_timestamp is: {}, grant_timestamp is: {}, last_use_delta is: {}, grant_time_delta is: {}".format(current_token['last_use_timestamp'], current_token['grant_timestamp'], last_use_delta, grant_time_delta))
			is_valid = (last_use_delta < 15 and grant_time_delta < 150)
		
		if self.auto_renew_token and not is_valid:
			self.logger.debug("Token has expired and auto_renew_token is set, renewing token.")
			if current_token:
				# Make sure we delete/logout the existing token so we don't leave stale ones on the controller
				(ret, response_code, response_data) = self.restLogout()
			(is_valid, response_code, response_data) = self.restLogin(self.hx_user, self._hx_password, self.auto_renew_token)
			
		return is_valid
		
	def restGetControllerVersion(self):

		request = self.build_request(self.build_api_route('version', min_api_version = 1))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	
	## Indicators
	#############

	# List indicator categories
	def restListCategories(self, limit=DEFAULT_LIMIT, offset=0, share_mode=None, sort_term=None, search_term=None, filter_term={}, query_terms = {}):
		
		endpoint_url = "indicator_categories"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if share_mode:
			params['share_mode'] = share_mode
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		params.update(query_terms)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	# Submit a new category
	def restCreateCategory(self, category_name, category_options = {}):

		request = self.build_request(self.build_api_route('indicator_categories/{0}'.format(category_name)), method = 'PUT', data = json.dumps(category_options))
		request.headers['If-None-Match'] = '*'
		
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# List all indicators
	def restListIndicators(self, limit=DEFAULT_LIMIT, offset=0, share_mode=None, search_term=None, sort_term=None, filter_term={}, query_terms={}):
		
		endpoint_url = "indicators"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if share_mode:
			params['share_mode'] = share_mode
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		params.update(query_terms)
			
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Add a new indicator
	def restAddIndicator(self, ioc_category, display_name, create_text=None, platforms=None, description=None):

		data = {
			'display_name' : display_name
		}
		if create_text:
			data['create_text'] = create_text
		if platforms:
			data['platforms'] = platforms
		if description:
			data['description'] = description
		
		request = self.build_request(self.build_api_route('indicators/{0}'.format(ioc_category)), method = 'POST', data = json.dumps(data))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)	
	
	# Delete an indicator by name
	def restDeleteIndicator(self, indicator_category, indicator_name):
		
		request = self.build_request(self.build_api_route('indicators/{0}/{1}'.format(indicator_category, indicator_name)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Delete a category
	def restDeleteCategory(self, indicator_category):
		
		request = self.build_request(self.build_api_route('indicator_categories/{0}'.format(indicator_category)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# List all conditions
	# TODO: Add has_alerts and enabled parameters
	def restListConditions(self, limit=DEFAULT_LIMIT, offset=0, has_share_mode=None, search_term=None, query_terms={}):
	
		endpoint_url = "conditions"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if has_share_mode:
			params['has_share_mode'] = has_share_mode
		if search_term:
			params['search'] = search_term
		params.update(query_terms)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = param)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# Add a new condition
	def restAddCondition(self, ioc_category, ioc_guid, condition_class, condition_data):

		request = self.build_request(self.build_api_route('indicators/{0}/{1}/conditions/{2}'.format(ioc_category, ioc_guid, condition_class)), method = 'POST', data = condition_data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	# Grab conditions from an indicator
	# NOTE: limit for conditions is hard capped at 10000
	def restGetCondition(self, ioc_category, ioc_uri, condition_class, limit=10000):

		request = self.build_request(self.build_api_route('indicators/{0}/{1}/conditions/{2}?limit={3}'.format(ioc_category, ioc_uri, condition_class, limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restDeleteCondition(self, ioc_category, ioc_uri, condition_class, condition_uuid):

		request = self.build_request(self.build_api_route('indicators/{0}/{1}/conditions/{2}/{3}'.format(ioc_category, ioc_uri, condition_class, condition_uuid)), method = 'DELETE')
		(ret, response_code, response_data, response_headers) = self.handle_response(request)

		return(ret, response_code, response_data)

	# Get indicator based on condition
	def restGetIndicatorFromCondition(self, condition_id):

		request = self.build_request(self.build_api_route('conditions/{0}/indicators'.format(condition_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	def restGetConditionDetails(self, condition_id):
	
		request = self.build_request(self.build_api_route('conditions/{0}'.format(condition_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	## Acquisitions
	###############

	def restListAllAcquisitions(self, limit=DEFAULT_LIMIT, offset=0, filter_term={}):

		params = {
			'limit' : limit,
			'offset' : offset
		}

		params.update(filter_term)

		request = self.build_request(self.build_api_route('acqs'), method = 'GET', params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)

		return(ret, response_code, response_data)

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

	def restNewAcquisition(self, agent_id, scriptname, script, skip_base64 = False):
		
		if not skip_base64:
			script = HXAPI.b64(script)

		data = json.dumps({'name' : scriptname, 'script' : {'b64' : script}})
		
		request = self.build_request(self.build_api_route('hosts/{0}/live'.format(agent_id)), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# Get File Acquisition Status
	def restFileAcquisitionById(self, acq_id):

		data = None
		
		request = self.build_request(self.build_api_route('acqs/files/{0}'.format(acq_id)), method = 'GET', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# Get Data Acquisition Status
	def restDataAcquisitionByID(self, acq_id):

		data = None
		
		request = self.build_request(self.build_api_route('acqs/live/{0}'.format(acq_id)), method = 'GET', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# Get Data Acquisition Collection
	def restDataCollectionByID(self, acq_id):

		data = None
		
		request = self.build_request(self.build_api_route('acqs/live/{0}.mans'.format(acq_id)), method = 'GET', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	# List Bulk Acquisitions
	def restListBulkAcquisitions(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}):
		
		endpoint_url = "acqs/bulk"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		return(ret, response_code, response_data)


	# List hosts in Bulk acquisition
	def restListBulkHosts(self, bulk_id, limit=DEFAULT_LIMIT, offset=0, sort_term=None, filter_term=None, share_mode=None, search_term=None):
		
		endpoint_url = "acqs/bulk/{0}/hosts".format(bulk_id)
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if share_mode:
			params['share_mode'] = share_mode
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
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


	# Download an acquisition (file)
	def restDownloadFile(self, url, destination_file_path = None, accept = 'application/octet-stream'):

		request = self.build_request(url, accept = accept)
		try:
			response = self._session.send(request, stream = True)
			
			if not response.encoding:
				response.encoding = self.default_encoding
			
			if destination_file_path: 
				with open(destination_file_path, 'wb') as f:
					shutil.copyfileobj(response.raw, f)
				return(True, response.status_code, None)	
			else:
				return(True, response.status_code, response)
				
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
	def restNewBulkAcq(self, script, hostset_id = None, hosts = None, comment = None, platforms = '*', skip_base64=False):
		
		if not skip_base64:
			script = HXAPI.b64(script)
	
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
	def restListFileaq(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}):
		
		endpoint_url = "acqs/files"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
	
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restListTriages(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}):
		
		endpoint_url = "acqs/triages"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	#######################
	## Enterprise Search ##
	#######################

	def restListSearches(self, limit=DEFAULT_LIMIT, offset=0, sort_term=None, filter_term={}):
		
		endpoint_url = "searches"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)

		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	def restSubmitSweep(self, indicator, host_set, ignore_unsupported_items = False, skip_base64 = False, displayname = False):
		
		if not skip_base64:
			indicator = HXAPI.b64(indicator)
		
		data = {
			'indicator' : indicator, 
			'host_set' : {'_id' : int(host_set)}
		}
		
		if displayname:
			data['displayname'] = displayname
			
		params = None
		if self.hx_version >= [4,5,0]:
			params = {'ignore_unsupported_items' : str(ignore_unsupported_items).lower()}
		
		request = self.build_request(self.build_api_route('searches'), method = 'POST', params = params, data = json.dumps(data))
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

	def restGetSearchResults(self, search_id, limit=DEFAULT_LIMIT):

		request = self.build_request(self.build_api_route('searches/{0}/results?limit={1}'.format(search_id, limit)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)


	##########
	# Alerts #
	##########

	def restGetAlertID(self, alert_id):

		request = self.build_request(self.build_api_route('alerts/{0}'.format(alert_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restGetAlerts(self, limit=DEFAULT_LIMIT, offset=0, has_share_mode=None, sort_term='reported_at+desc', filter_term={}, resolution_term=None):
		
		endpoint_url = "alerts"
		params = {
			'limit' : limit,
			'offset' : offset
		}
		if has_share_mode:
			params['has_share_mode'] = has_share_mode
		if sort_term:
			params['sort'] = sort_term
		if resolution_term:
			params['resolution'] = resolution_term
		params.update(filter_term)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	# NOTE: this function does not return data in the usual way, the response is a list of alerts
	def restGetAlertsHost(self, agent_id, limit = DEFAULT_LIMIT):
	
		data = json.dumps({'agent._id' : [agent_id]})
	
		request = self.build_request(self.build_api_route('alerts/filter'), method = 'POST', data = data)
		(ret, response_code, response_data, response_headers) = self.handle_response(request, multiline_json = True, multiline_json_limit = limit, stream = True)
		
		if ret:
			from operator import itemgetter
			sorted_alert_list = sorted(response_data, key=itemgetter('reported_at'), reverse=True);
			return(True, response_code, sorted_alert_list)
		
		else:
			return(ret, response_code, response_data)
		
	# NOTE: this function does not return data in the usual way, the response is a list of alerts
	def restGetAlertsTime(self, start_date, end_date, limit = DEFAULT_LIMIT, filters=False):

		myquery = {'event_at' : 
							{'min' : '{0}T00:00:00.000Z'.format(start_date), 
							'max' : '{0}T23:59:59.999Z'.format(end_date)}
						}
		# Filters is a dict
		if filters:
			for filterkey, filterval in filters.items():
				myquery[filterkey] = filterval

		data = json.dumps(myquery)
							
		request = self.build_request(self.build_api_route('alerts/filter'), method = 'POST', data = data)
		
		(ret, response_code, response_data, response_headers) = self.handle_response(request, multiline_json = True, multiline_json_limit = limit, stream = True)
		
		if ret:
			from operator import itemgetter
			sorted_alert_list = sorted(response_data, key=itemgetter('reported_at'), reverse=True);
			return(True, response_code, sorted_alert_list)
		
		else:
			return(ret, response_code, response_data)
			


	########
	# Hosts
	########
		
	def restListHosts(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}, query_terms = {}):
		
		endpoint_url = "hosts"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		params.update(query_terms)

		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restDeleteHostByID(self, agent_id):
		
		request = self.build_request(self.build_api_route('hosts/{0}'.format(agent_id)), method = 'DELETE')
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
		
	def restListHostsets(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}):
		
		endpoint_url = "host_sets"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)

		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restListHostsInHostset(self, host_set_id, limit=DEFAULT_LIMIT, offset=0, sort_term=None, search_term=None, filter_term={}, query_terms={}):
		
		endpoint_url = "host_sets/{0}/hosts".format(host_set_id)
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		params.update(query_terms)

		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	def restModifyHostset(self, hostset_name, hostset_id, addlist = None, removelist = None):

		data = {}
		data['name'] = hostset_name
		data['changes'] = []
		data['changes'].append({})
		data['changes'][0]['command'] = "change"
		if addlist:
			data['changes'][0]['add'] = addlist
		if removelist:
			data['changes'][0]['remove'] = removelist

		request = self.build_request(self.build_api_route('host_sets/static/{0}'.format(hostset_id)), method = 'PUT', data = json.dumps(data))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)

	##################
	# Config Channels
	##################	
			
	def restListCustomConfigChannels(self, limit=DEFAULT_LIMIT, offset=0, sort_term=None, search_term=None, filter_term={}):
		
		endpoint_url = "host_policies/channels"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)
		
		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
	def restNewConfigChannel(self, name, description, priority, host_sets, conf):

		myhostsets = []
		for hs in host_sets:
			myhostsets.append({"_id": int(hs)})
		
		try:
			data = json.dumps({'name' : name, 'description' : description, 'priority' : int(priority), 'host_sets' : myhostsets, 'configuration' : json.loads(conf)})
			
			request = self.build_request(self.build_api_route('host_policies/channels'), method = 'POST', data = data)
			(ret, response_code, response_data, response_headers) = self.handle_response(request)
			
			return(ret, response_code, response_data)
		except ValueError:		
			self.logger.error("Failed to parse custom config channel JSON. Please verify your configuration.")
			return(False, None, None)
	
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


	##########
	# Policies
	##########
	
	def restListPolicies(self, limit=DEFAULT_LIMIT, offset=0, search_term=None, sort_term=None, filter_term={}):
		
		endpoint_url = "policies"
		params = {
			'limit' : limit,
			'offset' : offset
		}		
		if search_term:
			params['search'] = search_term
		if sort_term:
			params['sort'] = sort_term
		params.update(filter_term)

		request = self.build_request(self.build_api_route(endpoint_url), params = params)
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restGetPolicy(self, policy_id):
		
		request = self.build_request(self.build_api_route("policies/{0}".format(policy_id)))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restCreatePolicy(self, policy_json):
		
		request = self.build_request(self.build_api_route("policies"), method = 'POST', data = json.dumps(policy_json))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
	
		
	def restModifyPolicy(self, policy_id, policy_json):
	
		request = self.build_request(self.build_api_route("policies/{0}".format(policy_id)), method = 'PUT', data = json.dumps(policy_json))
		(ret, response_code, response_data, response_headers) = self.handle_response(request)
		
		return(ret, response_code, response_data)
		
	def restDeletePolicy(self, policy_id):
		
		request = self.build_request(self.build_api_route("policies/{0}".format(policy_id)), method = 'DELETE')
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
				return str(round(second_diff)) + " seconds ago"
			if second_diff < 120:
				return "a minute ago"
			if second_diff < 3600:
				return str(round(second_diff / 60)) + " minutes ago"
			if second_diff < 7200:
				return "an hour ago"
			if second_diff < 86400:
				return str(round(second_diff / 3600)) + " hours ago"
		if day_diff == 1:
			return "Yesterday"
		if day_diff < 7:
			return str(round(day_diff)) + " days ago"
		if day_diff < 31:
			return str(round(day_diff / 7)) + " weeks ago"
		if day_diff < 365:
			return str(round(day_diff / 30)) + " months ago"
		
		return str(round(day_diff / 365)) + " years ago"

	@staticmethod	
	def gt(dt_str):
		
		dt, _, us= dt_str.partition(".")
		dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
		us = int(us.rstrip("Z"), 10)
		return dt + datetime.timedelta(microseconds=us)

	@staticmethod	
	def gtNoUs(dt_str):
		
		dt = dt_str[0:(len(dt_str) - 5)]
		dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
		return dt
		
	"""
	Base64 encoding/decoding - Python 2/3 compatibility
	"""
	@staticmethod
	def b64(s, decode = False, decode_string = False, character_encoding = 'utf-8'):
		if decode:
			if decode_string:
				return base64.b64decode(s).decode(character_encoding)
			return base64.b64decode(s)
		
		try:
			return base64.b64encode(s).decode(character_encoding)
		except TypeError:
			if type(s) is str:
				s = s.encode(character_encoding)
			return base64.b64encode(s).decode(character_encoding)
	
	@staticmethod
	def compat_str(s, character_encoding = 'utf-8'):
		if s is None:
			return ''
		try:
			return unicode(s)
		except NameError:
			if type(s) is bytes:	
				return s.decode(character_encoding)
			else:
				return str(s)

	@staticmethod
	def dt_from_str(s, precision = 's'):
		format_string = '%Y-%m-%d %H:%M:%S'
		if precision == 'ms':
			format_string = '%Y-%m-%d %H:%M:%S.%f'
		elif '.' in s:
			s = s[:s.find('.'):]
		return datetime.datetime.strptime(s, format_string)
		
	@staticmethod
	def dt_to_str(s, precision = 's'):
		format_string = '%Y-%m-%d %H:%M:%S'
		if precision == 'ms':
			format_string = '%Y-%m-%d %H:%M:%S.%f'
		return datetime.datetime.strftime(s, format_string)
	
	# Returns a formatted date/time string for time range use with HX acquistion scripts
	@staticmethod
	def hx_strftime(d):
		return d.strftime("%Y-%m-%dT%H:%M:%SZ")
		