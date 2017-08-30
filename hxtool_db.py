#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import datetime
import uuid

try:
	import tinydb
	import tinydb.operations
except ImportError:
	print("hxtool_db requires the 'tinydb' module, please install it.")
	exit(1)

from hx_lib import *

class hxtool_db:
	def __init__(self, db_file):
		self._db = tinydb.TinyDB(db_file)
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
		return self._db.table('profile').all()
	
	"""
	Get a profile by id
	"""
	def profileGet(self, profile_id):
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
		return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadList(self, profile_id):
		return self._db.table('bulk_download').search((tinydb.Query()['profile_id'] == profile_id))
	
	def bulkDownloadUpdateHost(self, profile_id, bulk_download_id, host_id):
		with self._lock:
			e_id = self._db.table('bulk_download').update(self._db_update_nested_dict('hosts', host_id, {'downloaded' : True}), 
														(tinydb.Query()['profile_id'] == profile_id) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) &
														(tinydb.Query()['hosts'].any(host_id)))
			return self._db.table('bulk_download').update({'update_timestamp' : str(datetime.datetime.utcnow())}, eids = e_id)
																			
	def bulkDownloadStop(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').update({'stopped' : True}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').remove((tinydb.Query()['profile_id'] == profile_id) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) & 
														(tinydb.Query()['stopped'] == True))
	
	def stackJobCreate(self, profile_id, bulk_download_id, stack_type):
		r = None
		with self._lock:
			ts = str(datetime.datetime.utcnow())
			try:
				r = self._db.table('stacking').insert({'profile_id' : profile_id, 
														'bulk_download_id' : int(bulk_download_id), 
														'stopped' : False,
														'stack_type' : stack_type, 													
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
		return self._db.table('stacking').get(eid = int(stack_job_id))
	
	def stackJobGet(self, profile_id, bulk_download_id):
		return self._db.table('stacking').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobList(self, profile_id):
		return self._db.table('stacking').search((tinydb.Query()['profile_id'] == profile_id))
	
	def stackJobAddResult(self, profile_id, bulk_download_id, result):
		with self._lock:
			return self._db.table('stacking').update(self._db_append_to_list('results', result), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobUpdate(self, profile_id, bulk_download_id, last_index, last_groupby = []):
		with self._lock:
			return self._db.table('stacking').update({'last_index' : last_index, 'last_groupby' : last_groupby, 'update_timestamp' : str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobStop(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').update({'stopped' : True, 'update_timestamp' : str(datetime.datetime.utcnow())}, eids = [int(stack_job_id)])		
	
	def stackJobDelete(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').remove(eids = [int(stack_job_id)])
	
	def _db_update_nested_dict(self, dict_name, dict_key, dict_values):
		def transform(element):
			if type(dict_values) is dict:
				element[dict_name][dict_key].update(dict_values)
			else:
				element[dict_name][dict_key] = dict_values
		return transform
	
	def _db_append_to_list(self, list_name, value):
		def transform(element):
			if type(value) is list:
				element[list_name].extend(value)
			else:
				element[list_name].append(value)
			if element.has_key('update_timestamp'):
				element['update_timestamp'] =  str(datetime.datetime.utcnow())
		return transform
	
	def _db_update_dict_in_list(self, list_name, query_key, query_value, k, v):
		def transform(element):
			for i in element[list_name]:
				if i[query_key] == query_value:
					i[k] = v
					break
		return transform
	
	