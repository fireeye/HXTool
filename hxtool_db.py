#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import datetime
import uuid
import logging

try:
	import tinydb
	import tinydb.operations
except ImportError:
	print("hxtool_db requires the 'tinydb' module, please install it.")
	exit(1)

from hx_lib import *

class hxtool_db:
	def __init__(self, db_file, logger = logging.getLogger(__name__)):
		self.logger = logger
		# If we can't open the DB file, rename the existing one
		try:
			self._db = tinydb.TinyDB(db_file)
		except ValueError:
			logger.error("%s is not a TinyDB formatted database. Please move or rename this file before starting HXTool.", db_file)
			exit(1)
			
		
		self._lock = threading.Lock()
		
	def __exit__(self, exc_type, exc_value, traceback):
		if self._db:
			self._db.close()
	"""
	Add a profile
	Dictionary structure is:
	{
		'hx_name' : 'profile name to be displayed when referencing this profile',
		'hx_host' : 'the fully qualified domain name or IP address of the HX controller',
		'hx_port' : the integer port to use when communicating with the aforementioned HX controller
	}
	"""	
	def profileCreate(self, hx_name, hx_host, hx_port):
		# Generate a unique profile id
		profile_id = str(uuid.uuid4())
		r = None
		with self._lock:
			try:
				r = self._db.table('profile').insert({'profile_id' : profile_id, 'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})
			except:	
				self._db.table('profile').remove(eids = [r])
				raise
		return r
		
	"""
	List all profiles
	"""
	def profileList(self):
		with self._lock:
			return self._db.table('profile').all()
	
	"""
	Get a profile by id
	"""
	def profileGet(self, profile_id):
		with self._lock:
			return self._db.table('profile').get((tinydb.Query()['profile_id'] == profile_id))
			
	def profileUpdate(self, profile_id, hx_name, hx_host, hx_port):
		with self._lock:
			return self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, (tinydb.Query()['profile_id'] == profile_id))
		
	"""
	Delete a profile
	Also remove any background processor credentials associated with the profile
	"""
	def profileDelete(self, profile_id):
		self.backgroundProcessorCredentialRemove(profile_id)	
		with self._lock:
			return self._db.table('profile').remove((tinydb.Query()['profile_id'] == profile_id))
		
	def backgroundProcessorCredentialCreate(self, profile_id, hx_api_username, iv, salt, hx_api_encrypted_password):
		r = None
		with self._lock:
			try:
				r = self._db.table('background_processor_credential').insert({'profile_id' : profile_id, 'hx_api_username' : hx_api_username, 'iv' : iv, 'salt': salt, 'hx_api_encrypted_password' : hx_api_encrypted_password})
			except:
				self._db.table('background_processor_credential').remove(eids = [r])
				raise
		return r
		
	def backgroundProcessorCredentialRemove(self, profile_id):
		with self._lock:
			return self._db.table('background_processor_credential').remove((tinydb.Query()['profile_id'] == profile_id))
			
	def backgroundProcessorCredentialGet(self, profile_id):
		with self._lock:
			return self._db.table('background_processor_credential').get((tinydb.Query()['profile_id'] == profile_id))
		
	def alertCreate(self, profile_id, hx_alert_id):
		r = self.alertGet(profile_id, hx_alert_id)
		if not r:
			with self._lock:
				try:
					r = self._db.table('alert').insert({'profile_id' : profile_id, 'hx_alert_id' : int(hx_alert_id), 'annotations' : []})
				except:
					self._db.table('alert').remove(eids = [r])
					raise
		else:
			r = r.eid
		return r
	
	def alertGet(self, profile_id, hx_alert_id):
		with self._lock:
			return self._db.table('alert').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
	
	def alertAddAnnotation(self, profile_id, hx_alert_id, annotation, state, create_user):
		with self._lock:
			return self._db.table('alert').update(self._db_append_to_list('annotations', {'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : str(datetime.datetime.utcnow())}), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
		
	def bulkDownloadCreate(self, profile_id, bulk_download_id, hosts, hostset_id = -1, hostset_name = None, post_download_handler = None):
		r = None
		with self._lock:
			try:
				r = self._db.table('bulk_download').insert({'profile_id' : profile_id, 
															'bulk_download_id': int(bulk_download_id), 
															'hosts' : hosts, 
															'hostset_id' : int(hostset_id),
															'hostset_name' : hostset_name,		
															'stopped' : False, 
															'post_download_handler' : post_download_handler, 
															'create_timestamp' : str(datetime.datetime.utcnow()), 
															'update_timestamp' : str(datetime.datetime.utcnow())})
			except:
				self._db.table('bulk_download').remove(eids = [r])
				raise
		return r		
	
	def bulkDownloadGet(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadList(self, profile_id):
		with self._lock:
			return self._db.table('bulk_download').search((tinydb.Query()['profile_id'] == profile_id))
	
	def bulkDownloadUpdateHost(self, profile_id, bulk_download_id, host_id):
		with self._lock:
			e_id = self._db.table('bulk_download').update(self._db_update_nested_dict('hosts', host_id, {'downloaded' : True}), 
														(tinydb.Query()['profile_id'] == profile_id) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) &
														(tinydb.Query()['hosts'].any(host_id)))
			return e_id
																			
	def bulkDownloadStop(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').update({'stopped' : True}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').remove((tinydb.Query()['profile_id'] == profile_id) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) & 
														(tinydb.Query()['stopped'] == True))
	
	def fileListingCreate(self, profile_id, username, bulk_download_id, path, regex, depth, display_name, api_mode=False):
		r = None
		with self._lock:
			ts = str(datetime.datetime.utcnow())
			try:
				r = self._db.table('file_listing').insert({'profile_id' : profile_id, 
														'display_name': display_name,
														'bulk_download_id' : int(bulk_download_id),
														'username': username,
														'stopped' : False,
														'files' : [],
														'cfg': {
															'path': path,
															'regex': regex,
															'depth': depth,
															'api_mode': api_mode
														},
														'create_timestamp' : ts, 
														'update_timestamp' : ts
														})
			except:
				self._db.table('file_listing').remove(eids = [r])
				raise
		return r
		
	def fileListingAddResult(self, profile_id, bulk_download_id, result):
		with self._lock:
			return self._db.table('file_listing').update(self._db_append_to_list('files', result), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def fileListingGetByBulkId(self, profile_id, bulk_download_id):
		with self._lock:
			result = self._db.table('file_listing').search((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
			return result and result[0] or None
	
	def fileListingGetById(self, flid):
		with self._lock:
			return self._db.table('file_listing').get(eid = int(flid))
	
	def fileListingList(self, profile_id):
		with self._lock:
			return self._db.table('file_listing').search(tinydb.Query()['profile_id'] == profile_id)

	def fileListingStop(self, file_listing_id):
		with self._lock:
			return self._db.table('file_listing').update({'stopped' : True, 'update_timestamp' : str(datetime.datetime.utcnow())}, eids = [int(file_listing_id)])		
	
	def fileListingDelete(self, file_listing_id):
		with self._lock:
			return self._db.table('file_listing').remove(eids = [int(file_listing_id)])
	
	def multiFileCreate(self, username, profile_id, display_name=None, file_listing_id=None, api_mode=False):
		r = None
		with self._lock:
			ts = str(datetime.datetime.utcnow())
			try:
				return self._db.table('multi_file').insert({
					'display_name': display_name or "Unnamed File Request",
					'username': username,
					'profile_id' : profile_id,
					'files': [],
					'stopped' : False,
					'api_mode': api_mode,
					'create_timestamp' : ts, 
					'update_timestamp' : ts,
					'file_listing_id': file_listing_id
				})
			except:
				#TODO: Not sure if the value returns that we'd ever see an exception
				if r:
					self._db.table('multi_file').remove(eids = [r])
				raise
		return None

	def multiFileAddJob(self, multi_file_id, job):
		try:
			with self._lock:
				return self._db.table('multi_file').update(self._db_append_to_list('files', job), eids=[int(multi_file_id)])
		except:
			return None

	def multiFileList(self, profile_id):
		with self._lock:
			return self._db.table('multi_file').search(tinydb.Query()['profile_id'] == profile_id)

	def multiFileGetById(self, multi_file_id):
		with self._lock:
			return self._db.table('multi_file').get(eid = int(multi_file_id))

	def multiFileUpdateFile(self, profile_id, multi_file_id, acquisition_id):
		try:
			with self._lock:
				eids = self._db.table('multi_file').update(self._db_update_dict_in_list('files', 'acquisition_id', acquisition_id, 'downloaded', True), eids=[int(multi_file_id)])
				return eids
		except:
			return None
																			
	def multiFileStop(self, multi_file_id):
		with self._lock:
			return self._db.table('multi_file').update({'stopped' : True, 'update_timestamp' : str(datetime.datetime.utcnow())}, eids = [int(multi_file_id)])		
	
	def multiFileDelete(self, multi_file_id):
		with self._lock:
			return self._db.table('multi_file').remove(eids = [int(multi_file_id)])
	
	def stackJobCreate(self, profile_id, bulk_download_id, stack_type):
		r = None
		with self._lock:
			ts = str(datetime.datetime.utcnow())
			try:
				r = self._db.table('stacking').insert({'profile_id' : profile_id, 
														'bulk_download_id' : int(bulk_download_id), 
														'stopped' : False,
														'stack_type' : stack_type,
														'hosts' : [],		
														'results' : [],
														'last_index' : None,
														'last_groupby' : [],
														'create_timestamp' : ts, 
														'update_timestamp' : ts
														})
			except:
				self._db.table('stacking').remove(eids = [r])
				raise
		return r
		
	def stackJobGetById(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').get(eid = int(stack_job_id))
	
	def stackJobGet(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('stacking').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobList(self, profile_id):
		with self._lock:
			return self._db.table('stacking').search((tinydb.Query()['profile_id'] == profile_id))
	
	def stackJobAddResult(self, profile_id, bulk_download_id, hostname, result):
		with self._lock:
			e_id = self._db.table('stacking').update(self._db_append_to_list('results', result), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
			return self._db.table('stacking').update(self._db_append_to_list('hosts', {'hostname' : hostname, 'processed' : True}), eids = e_id)
			
			
	def stackJobUpdateIndex(self, profile_id, bulk_download_id, last_index):
		with self._lock:
			return self._db.table('stacking').update({'last_index' : last_index, 'update_timestamp' : str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobUpdateGroupBy(self, profile_id, bulk_download_id, last_groupby):
		with self._lock:
			return self._db.table('stacking').update({'last_groupby' : last_groupby, 'update_timestamp' : str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobStop(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').update({'stopped' : True, 'update_timestamp' : str(datetime.datetime.utcnow())}, eids = [int(stack_job_id)])		
	
	def stackJobDelete(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').remove(eids = [int(stack_job_id)])
	
	def sessionCreate(self, session_id, session_nonce):
		with self._lock:
			return self._db.table('session').insert({'session_id' 		: session_id,
													'session_nonce' 	: session_nonce,
													'session_signature'	: None,
													'session_data'		: None,
													'update_timestamp'	: None})
	
	def sessionGet(self, session_id):
		with self._lock:
			return self._db.table('session').get((tinydb.Query()['session_id'] == session_id))
		
	def sessionUpdate(self, session_id, session_data, session_signature):
		with self._lock:
			return self._db.table('session').update({'session_data' : session_data, 'session_signature' : session_signature, 'update_timestamp' : str(datetime.datetime.utcnow())}, (tinydb.Query()['session_id'] == session_id))
		
	def sessionDelete(self, session_id):
		with self._lock:
			return self._db.table('session').remove((tinydb.Query()['session_id'] == session_id))
	
	def _db_update_nested_dict(self, dict_name, dict_key, dict_values, update_timestamp = True):
		def transform(element):
			if type(dict_values) is dict:
				element[dict_name][dict_key].update(dict_values)
			else:
				element[dict_name][dict_key] = dict_values
			if update_timestamp and 'update_timestamp' in element:
					element['update_timestamp'] =  str(datetime.datetime.utcnow())		
		return transform
	
	def _db_append_to_list(self, list_name, value, update_timestamp = True):
		def transform(element):
			if type(value) is list:
				element[list_name].extend(value)
			else:
				element[list_name].append(value)
			if update_timestamp and 'update_timestamp' in element:
				element['update_timestamp'] =  str(datetime.datetime.utcnow())
		return transform
	
	def _db_update_dict_in_list(self, list_name, query_key, query_value, k, v, update_timestamp = True):
		def transform(element):
			for i in element[list_name]:
				if i[query_key] == query_value:
					i[k] = v
					break
			if update_timestamp and 'update_timestamp' in element:
				element['update_timestamp'] =  str(datetime.datetime.utcnow())		
		return transform
	
	
