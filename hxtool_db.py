#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import datetime

try:
	import tinydb
	import tinydb.operations
except ImportError:
	print("hxtool_db requires the TinyDB module, please install it.")
	exit(1)

from hx_lib import *

class hxtool_db:
	def __init__(self, db_file):
		self._db = tinydb.TinyDB(db_file)
		self._lock = threading.RLock()
		
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
		with self._lock:
			return self._db.table('profile').insert({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})
		
	"""
	List all profiles
	"""
	def profileList(self):
		profiles = self._db.table('profile').all()
		for p in profiles: p['profile_id'] = p.eid
		return profiles
	
	"""
	Get a profile by id
	"""
	def profileGet(self, profile_id):
		profile = self._db.table('profile').get(eid = int(profile_id))
		if profile:
			profile['profile_id'] = profile.eid
			return profile
		else:
			return None
			
	def profileUpdate(self, profile_id, hx_name, hx_host, hx_port):
		with self._lock:
			return self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, eids = [int(profile_id)])
		
	"""
	Delete a profile
	Also remove any background processor credentials associated with the profile
	"""
	def profileDelete(self, profile_id):
		self.backgroundProcessorCredentialRemove(profile_id)	
		with self._lock:
			return self._db.table('profile').remove(eids = [int(profile_id)])
		
	def backgroundProcessorCredentialCreate(self, profile_id, hx_api_username, iv, salt, hx_api_encrypted_password):
		with self._lock:
			return self._db.table('background_processor_credential').insert({'profile_id' : int(profile_id), 'hx_api_username' : hx_api_username, 'iv' : iv, 'salt': salt, 'hx_api_encrypted_password' : hx_api_encrypted_password})
	
	def backgroundProcessorCredentialRemove(self, profile_id):
		with self._lock:
			return self._db.table('background_processor_credential').remove((tinydb.Query()['profile_id'] == int(profile_id)))
			
	def backgroundProcessorCredentialGet(self, profile_id):
		return self._db.table('background_processor_credential').get((tinydb.Query()['profile_id'] == int(profile_id)))
		
	def alertCreate(self, profile_id, hx_alert_id):
		r = self.alertGet(profile_id, hx_alert_id)
		if not r:
			with self._lock:
				r = self._db.table('alert').insert({'profile_id' : int(profile_id), 'hx_alert_id' : int(hx_alert_id), 'annotations' : []})
		else:
			r = r.eid
		return r
	
	def alertGet(self, profile_id, hx_alert_id):
		return self._db.table('alert').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
	
	def alertAddAnnotation(self, profile_id, hx_alert_id, annotation, state, create_user):
		alert = self.alertGet(profile_id, hx_alert_id)
		with self._lock:
			alert['annotations'].append({'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : str(datetime.datetime.utcnow())})		
			return self._db.table('alert').update(alert, eids = [alert.eid])
		
	def bulkDownloadCreate(self, profile_id, bulk_download_id, hosts, hostset_id = -1, stack_job = False):
		with self._lock:
			return self._db.table('bulk_download').insert({'profile_id' : int(profile_id), 
														'bulk_download_id': int(bulk_download_id), 
														'hosts' : hosts, 
														'hostset_id' : hostset_id, 
														'stopped' : False, 
														'stack_job' : stack_job, 
														'create_timestamp' : str(datetime.datetime.utcnow()), 
														'update_timestamp' : str(datetime.datetime.utcnow())})
	
	def bulkDownloadGet(self, profile_id, bulk_download_id):
		return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadList(self, profile_id):
		return self._db.table('bulk_download').search((tinydb.Query()['profile_id'] == int(profile_id)))
	
	def bulkDownloadUpdateHost(self, profile_id, bulk_download_id, host_id):
		with self._lock:
			e_id = self._db.table('bulk_download').update(self._db_update_nested_dict('hosts', host_id, 'downloaded', True), 
														(tinydb.Query()['profile_id'] == int(profile_id)) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) &
														(tinydb.Query()['hosts'].any(host_id)))
			return self._db.table('bulk_download').update({'update_timestamp' : str(datetime.datetime.utcnow())}, eids = e_id)
																			
	def bulkDownloadStop(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').update({'stopped' : True}, (tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').remove((tinydb.Query()['profile_id'] == int(profile_id)) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) & 
														(tinydb.Query()['stopped'] == True))
	
	def stackJobCreate(self, profile_id, bulk_download_id, script_type, hostset_id = -1):
		with self._lock:
			return self._db.table('stacking').insert({'profile_id' : int(profile_id), 
													'bulk_download_id' : int(bulk_download_id), 
													'hostset_id' : int(hostset_id),
													'stopped' : False,		
													'hosts' : {}, 
													'script_type' : script_type, 
													'stack_by_field' : None,
													'create_timestamp' : str(datetime.datetime.utcnow()), 
													'update_timestamp' : str(datetime.datetime.utcnow())
													})
	def stackJobGetById(self, stack_job_id):
		return self._db.table('stacking').get(eid = int(stack_job_id))
	
	def stackJobGet(self, profile_id, bulk_download_id):
		return self._db.table('stacking').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobList(self, profile_id):
		return self._db.table('stacking').search((tinydb.Query()['profile_id'] == int(profile_id)))
	
	def stackJobUpdate(self, profile_id, bulk_download_id, stack_by_field):
		with self._lock:
			return self._db.table('stacking').update({'stack_by_field' : stack_by_field, 'update_timestamp' : str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobAddHost(self, profile_id, bulk_download_id, host_id, results):
		with self._lock:
			e_id = self._db.table('stacking').update(self._db_update_nested_dict('hosts', host_id, 'results', results), 
													(tinydb.Query()['profile_id'] == int(profile_id)) & 
													(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
			return self._db.table('stacking').update({'update_timestamp' : str(datetime.datetime.utcnow())}, eids = e_id)
	
	def stackJobStop(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').update({'stopped' : True, 'update_timestamp' : str(datetime.datetime.utcnow())}, eids = [int(stack_job_id)])		
	
	def stackJobDelete(self, stack_job_id):
		with self._lock:
			return self._db.table('stacking').remove(eids = [int(stack_job_id)])
	
	def _db_update_nested_dict(self, dict_name, query_key, k, v):
		def transform(element):
			if query_key in element[dict_name]:
				element[dict_name][query_key][k] = v
			else:
				element[dict_name][query_key] = {k : v}
		return transform
	
	def _db_update_dict_in_list(self, list_name, query_key, query_value, k, v):
		def transform(element):
			for i in element[list_name]:
				if i[query_key] == query_value:
					i[k] = v
					break
		return transform