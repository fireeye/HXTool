#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import datetime
import logging

import hxtool_global
from hxtool_util import *
from hx_lib import *

try:
	import tinydb
	import tinydb.operations
	from tinydb.storages import JSONStorage
	from tinydb.middlewares import CachingMiddleware
except ImportError:
	print("hxtool_db requires the 'tinydb' module, please install it.")
	exit(1)

from hx_lib import *

class hxtool_db:
	def __init__(self, db_file, logger = hxtool_global.get_logger(__name__), write_cache_size = 10):
		self.logger = logger
		# If we can't open the DB file, rename the existing one
		try:
			CachingMiddleware.WRITE_CACHE_SIZE = write_cache_size
			self._db = tinydb.TinyDB(db_file, storage=CachingMiddleware(JSONStorage))
		except ValueError:
			self.logger.error("%s is not a TinyDB formatted database. Please move or rename this file before starting HXTool.", db_file)
			exit(1)
			
		self._lock = threading.Lock()
		self.check_schema()
		
	def close(self):
		if self._db:
			self._db.close()
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.close()
		
	
	def check_schema(self):
		current_schema_version = None
		with self._lock:
			current_schema_version = self._db.table('schema_version').get(eid = 1)
			if current_schema_version:
				current_schema_version = int(current_schema_version['schema_version'])
		if not current_schema_version:
			self.logger.warning("The current HXTool database has no schema version set, a DB schema upgrade may be required.")
			if self.upgrade_schema():
				self.logger.info("Database schema upgraded successfully.")
				self._db.table('schema_version').insert({'schema_version' : hxtool_global.hxtool_schema_version})
		elif current_schema_version < hxtool_global.hxtool_schema_version:
			self.logger.warning("The current HXTool database has a schema version: {} that is older than the current version of: {}, a DB schema upgrade may be required.".format(current_schema_version, hxtool_global.hxtool_schema_version))
			if self.upgrade_schema():
				self.logger.info("Database schema upgraded successfully.")
				self._db.table('schema_version').update({'schema_version' : hxtool_global.hxtool_schema_version}, eids = [1])
		
	def upgrade_schema(self):
		try:
			with self._lock:
				# Schema upgrade code - will change from release to release
				
				# Upgrade stack and file listing jobs to 4.0 schema
				for r in self._db.table('stacking').all():
					if 'bulk_download_id' in r and r['bulk_download_id'] > 0:
						b = self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == r['profile_id']) & (tinydb.Query()['bulk_download_id'] == r['bulk_download_id']))
						if b:
							self._db.table('stacking').update({'bulk_download_eid' : b.eid}, eids = [r.eid])
							self._db.table('stacking').update(tinydb.operations.delete('bulk_download_id'), eids = [r.eid])
				
				for r in self._db.table('file_listing').all():
					if 'bulk_download_id' in r and r['bulk_download_id'] > 0:
						b = self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == r['profile_id']) & (tinydb.Query()['bulk_download_id'] == r['bulk_download_id']))
						if b:
							self._db.table('file_listing').update({'bulk_download_eid' : b.eid}, eids = [r.eid])
							self._db.table('file_listing').update(tinydb.operations.delete('bulk_download_id'), eids = [r.eid])
				
				# Rename bulk_download_id to bulk_acquisition_id in the bulk_download table, post_download_handler to task_profile
				for r in self._db.table('bulk_download').all():
					if 'bulk_download_id' in r and r['bulk_download_id'] > 0:
						self._db.table('bulk_download').update({'bulk_acquisition_id' : r['bulk_download_id']}, eids = [r.eid])
						self._db.table('bulk_download').update(tinydb.operations.delete('bulk_download_id'), eids = [r.eid])
					if 'post_download_handler' in r:	
						self._db.table('bulk_download').update({'task_profile' : r['post_download_handler']}, eids = [r.eid])
						self._db.table('bulk_download').update(tinydb.operations.delete('post_download_handler'), eids = [r.eid])
				
			return True
		except:
			raise
			return False
			
	
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
		profile_id = str(secure_uuid4())
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

	def alertList(self, profile_id):
		with self._lock:
			return self._db.table('alert').search((tinydb.Query()['profile_id'] == profile_id))

	def alertGet(self, profile_id, hx_alert_id):
		with self._lock:
			return self._db.table('alert').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
	
	def alertAddAnnotation(self, profile_id, hx_alert_id, annotation, state, create_user):
		with self._lock:
			return self._db.table('alert').update(self._db_append_to_list('annotations', {'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
		
	def bulkDownloadCreate(self, profile_id, hostset_name = None, hostset_id = None, task_profile = None):
		r = None
		with self._lock:
			try:
				ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
				r = self._db.table('bulk_download').insert({'profile_id' : profile_id, 
															'hostset_id' : int(hostset_id),
															'hostset_name' : hostset_name,
															'hosts'	: {},
															'task_profile' : task_profile,
															'stopped' : False,
															'complete' : False,
															'create_timestamp' : ts, 
															'update_timestamp' : ts})
			except:
				self._db.table('bulk_download').remove(eids = [r])
				raise
		return r		
	
	def bulkDownloadGet(self, bulk_download_eid = None, profile_id = None, bulk_acquisition_id = None):
		if bulk_download_eid:
			with self._lock:
				return self._db.table('bulk_download').get(eid = int(bulk_download_eid))
		elif profile_id and bulk_acquisition_id:
			with self._lock:
				return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_acquisition_id'] == bulk_acquisition_id))
	
	def bulkDownloadList(self, profile_id):
		with self._lock:
			return self._db.table('bulk_download').search((tinydb.Query()['profile_id'] == profile_id))
	
	def bulkDownloadUpdate(self, bulk_download_eid, bulk_acquisition_id = None, hosts = None, stopped = None, complete = None):
		d = {'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}
		
		if bulk_acquisition_id is not None:
			d['bulk_acquisition_id'] = bulk_acquisition_id
		if hosts is not None:
			d['hosts'] = hosts
		if stopped is not None:
			d['stopped'] = stopped
		if complete is not None:
			d['complete'] = complete

		with self._lock:
			return self._db.table('bulk_download').update(d, eids = [int(bulk_download_eid)])
			
	def bulkDownloadUpdateHost(self, bulk_download_eid, host_id, downloaded = None, hostname = None):
		d = {}
			
		if downloaded is not None:
			d['downloaded'] = downloaded
		if hostname is not None:
			d['hostname'] = hostname
		
		with self._lock:
			return self._db.table('bulk_download').update(self._db_update_nested_dict('hosts', host_id, d), eids = [int(bulk_download_eid)])
	
	def bulkDownloadDeleteHost(self, bulk_download_eid, host_id):
		with self._lock:
			return self._db.table('bulk_download').update(self._db_delete_from_nested_dict('hosts', host_id), eids = [int(bulk_download_eid)])		
	
	def bulkDownloadDelete(self, bulk_download_eid):
		with self._lock:
			return self._db.table('bulk_download').remove(eids = [int(bulk_download_eid)])
	
	def fileListingCreate(self, profile_id, username, bulk_download_eid, path, regex, depth, display_name, api_mode=False):
		r = None
		with self._lock:
			ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
			try:
				r = self._db.table('file_listing').insert({'profile_id' : profile_id, 
														'display_name': display_name,
														'bulk_download_eid' : int(bulk_download_eid),
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
		
	def fileListingAddResult(self, profile_id, bulk_download_eid, result):
		with self._lock:
			return self._db.table('file_listing').update(self._db_append_to_list('files', result), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == int(bulk_download_eid)))
	
	def fileListingGetByBulkId(self, profile_id, bulk_download_eid):
		with self._lock:
			result = self._db.table('file_listing').search((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == int(bulk_download_eid)))
			return result and result[0] or None
	
	def fileListingGetById(self, flid):
		with self._lock:
			return self._db.table('file_listing').get(eid = int(flid))
	
	def fileListingList(self, profile_id):
		with self._lock:
			return self._db.table('file_listing').search(tinydb.Query()['profile_id'] == profile_id)

	def fileListingStop(self, file_listing_id):
		with self._lock:
			return self._db.table('file_listing').update({'stopped' : True, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, eids = [int(file_listing_id)])		
	
	def fileListingDelete(self, file_listing_id):
		with self._lock:
			return self._db.table('file_listing').remove(eids = [int(file_listing_id)])
	
	def multiFileCreate(self, username, profile_id, display_name=None, file_listing_id=None, api_mode=False):
		r = None
		with self._lock:
			ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
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
			return self._db.table('multi_file').update({'stopped' : True, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, eids = [int(multi_file_id)])		
	
	def multiFileDelete(self, multi_file_id):
		with self._lock:
			return self._db.table('multi_file').remove(eids = [int(multi_file_id)])
	
	def stackJobCreate(self, profile_id, bulk_download_eid, stack_type):
		r = None
		with self._lock:
			ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
			try:
				r = self._db.table('stacking').insert({'profile_id' : profile_id, 
														'bulk_download_eid' : int(bulk_download_eid), 
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
		
	def stackJobGet(self, stack_job_eid = None, profile_id = None, bulk_download_eid = None):
		if stack_job_eid:
			with self._lock:
				return self._db.table('stacking').get(eid = int(stack_job_eid))
		elif profile_id and bulk_download_eid:		
			with self._lock:
				return self._db.table('stacking').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == bulk_download_eid))
		
	def stackJobList(self, profile_id):
		with self._lock:
			return self._db.table('stacking').search((tinydb.Query()['profile_id'] == profile_id))
	
	def stackJobAddResult(self, profile_id, bulk_download_eid, hostname, result):
		with self._lock:
			e_id = self._db.table('stacking').update(self._db_append_to_list('results', result), (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == int(bulk_download_eid)))
			return self._db.table('stacking').update(self._db_append_to_list('hosts', {'hostname' : hostname, 'processed' : True}), eids = e_id)
			
			
	def stackJobUpdateIndex(self, profile_id, bulk_download_eid, last_index):
		with self._lock:
			return self._db.table('stacking').update({'last_index' : last_index, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == int(bulk_download_eid)))
	
	def stackJobUpdateGroupBy(self, profile_id, bulk_download_eid, last_groupby):
		with self._lock:
			return self._db.table('stacking').update({'last_groupby' : last_groupby, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['bulk_download_eid'] == int(bulk_download_eid)))
	
	def stackJobStop(self, stack_job_eid):
		with self._lock:
			return self._db.table('stacking').update({'stopped' : True, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, eids = [int(stack_job_eid)])		
	
	def stackJobDelete(self, stack_job_eid):
		with self._lock:
			return self._db.table('stacking').remove(eids = [int(stack_job_eid)])
	
	def sessionCreate(self, session_id):
		with self._lock:
			return self._db.table('session').insert({'session_id' 		: session_id,
													'session_data'		: {},
													'update_timestamp'	: HXAPI.dt_to_str(datetime.datetime.utcnow())})
	
	def sessionList(self):
		with self._lock:
			return self._db.table('session').all()
	
	def sessionGet(self, session_id):
		with self._lock:
			return self._db.table('session').get((tinydb.Query()['session_id'] == session_id))
		
	def sessionUpdate(self, session_id, session_data):
		with self._lock:
			return self._db.table('session').update({'session_data' : session_data, 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())}, (tinydb.Query()['session_id'] == session_id))
		
	def sessionDelete(self, session_id):
		with self._lock:
			return self._db.table('session').remove((tinydb.Query()['session_id'] == session_id))
	
	def scriptCreate(self, scriptname, script, username):
		with self._lock:
			return self._db.table('scripts').insert({'script_id' : str(uuid.uuid4()), 
														'scriptname': str(scriptname), 
														'username' : str(username),
														'script' : str(script), 
														'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
														'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})		

	def scriptList(self):
		with self._lock:
			return self._db.table('scripts').all()

	def scriptDelete(self, script_id):
		with self._lock:
			return self._db.table('scripts').remove((tinydb.Query()['script_id'] == script_id))

	def scriptGet(self, script_id):
		with self._lock:
			return self._db.table('scripts').get((tinydb.Query()['script_id'] == script_id))


	def oiocCreate(self, iocname, ioc, username):
		with self._lock:
			return self._db.table('openioc').insert({'ioc_id' : str(uuid.uuid4()), 
														'iocname': str(iocname), 
														'username' : str(username),
														'ioc' : str(ioc), 
														'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
														'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})		

	def oiocList(self):
		with self._lock:
			return self._db.table('openioc').all()

	def oiocDelete(self, ioc_id):
		with self._lock:
			return self._db.table('openioc').remove((tinydb.Query()['ioc_id'] == ioc_id))

	def oiocGet(self, ioc_id):
		with self._lock:
			return self._db.table('openioc').get((tinydb.Query()['ioc_id'] == ioc_id))

	def taskCreate(self, serialized_task):
		with self._lock:
			return self._db.table('tasks').insert(serialized_task)
	
	def taskList(self):
		with self._lock:
			return self._db.table('tasks').all()
	
	def taskGet(self, profile_id, task_id):
		with self._lock:
			return self._db.table('tasks').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['task_id'] == task_id))
	
	def taskUpdate(self, profile_id, task_id, serialized_task):
		with self._lock:
			return self._db.table('tasks').update(serialized_task, (tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['task_id'] == task_id))
	
	def taskDelete(self, profile_id, task_id):
		with self._lock:
			return self._db.table('tasks').remove((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['task_id'] == task_id))
			
	def taskProfileAdd(self, name, actor, params):
		with self._lock:
			return self._db.table('taskprofiles').insert({'taskprofile_id' : str(uuid.uuid4()), 
														'name': str(name), 
														'actor' : str(actor),
														'params' : params, 
														'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
														'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})

	def taskProfileList(self):
		with self._lock:
			return self._db.table('taskprofiles').all()
			
	def taskProfileGet(self, taskprofile_id):
		with self._lock:
			return self._db.table('taskprofiles').get((tinydb.Query()['taskprofile_id'] == taskprofile_id))

	def taskProfileDelete(self, taskprofile_id):
		with self._lock:
			return self._db.table('taskprofiles').remove((tinydb.Query()['taskprofile_id'] == taskprofile_id))


	def auditCreate(self, profile_id, host_id, hostname, generator, start_time, end_time, results):
		with self._lock:
			return self._db.table('audits').insert({'profile_id' : profile_id,
													'audit_id'	: str(secure_uuid4()),
													'host_id:'	: host_id,
													'hostname'	: hostname,
													'generator'	: generator,
													'start_time': start_time,
													'end_time'	: end_time,
													'results'	: results})
	
	def auditList(self, profile_id):
		with self._lock:
			return self._db.table('audits').get((tinydb.Query()['profile_id'] == profile_id))
	
	def auditGet(self, profile_id, audit_id):
		with self._lock:
			return self._db.table('audits').get((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['audit_id']))
			
	def auditDelete(self, profile_id, audit_id):
		with self._lock:
			return self._db.table('audits').remove((tinydb.Query()['profile_id'] == profile_id) & (tinydb.Query()['audit_id']))
			
			
				
	def _db_update_nested_dict(self, dict_name, dict_key, dict_values, update_timestamp = True):
		def transform(element):
			if not dict_key in element[dict_name]:
				element[dict_name][dict_key] = dict_values
			else:
				if type(dict_values) is dict:
					element[dict_name][dict_key].update(dict_values)
				else:
					element[dict_name][dict_key] = dict_values
			if update_timestamp and 'update_timestamp' in element:
					element['update_timestamp'] =  HXAPI.dt_to_str(datetime.datetime.utcnow())		
		return transform
		
	def _db_delete_from_nested_dict(self, dict_name, dict_key, update_timestamp = True):
		def transform(element):
			if dict_key in element[dict_name]:
				del element[dict_name][dict_key]
			if update_timestamp and 'update_timestamp' in element:
					element['update_timestamp'] =  HXAPI.dt_to_str(datetime.datetime.utcnow())	
		return transform
	
	def _db_append_to_list(self, list_name, value, update_timestamp = True):
		def transform(element):
			if type(value) is list:
				element[list_name].extend(value)
			else:
				element[list_name].append(value)
			if update_timestamp and 'update_timestamp' in element:
				element['update_timestamp'] =  HXAPI.dt_to_str(datetime.datetime.utcnow())
		return transform
	
	def _db_update_dict_in_list(self, list_name, query_key, query_value, k, v, update_timestamp = True):
		def transform(element):
			for i in element[list_name]:
				if i[query_key] == query_value:
					i[k] = v
					break
			if update_timestamp and 'update_timestamp' in element:
				element['update_timestamp'] =  HXAPI.dt_to_str(datetime.datetime.utcnow())		
		return transform