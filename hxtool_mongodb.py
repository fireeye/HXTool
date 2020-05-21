#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from pymongo import MongoClient
except ImportError:
	print("HXTool is configured to use MongoDB. Please install the 'pymongo' Python module")
	exit(1)

import datetime
import json
import hxtool_vars
import hxtool_logging
from hx_lib import HXAPI
from hxtool_util import secure_uuid4
import pickle
from bson.binary import Binary
from bson.objectid import ObjectId

logger = hxtool_logging.getLogger(__name__)

# Emulate existing TinyDB architecture
class tinydb_emulated_dict(dict):
	# Ugly way of dealing with MongoDB ObjectId and JSON encoding
	def __setitem__(self, key, value):
		if key == '_id':
			value = str(value)
		super(tinydb_emulated_dict, self).__setitem__(key, value)
	
	@property
	def doc_id(self):
		return str(self['_id'])

class hxtool_mongodb:
	def __init__(self, db_host, db_port, db_user, db_pass, db_auth_source, db_auth_mechanism):
		try:
			self._client = MongoClient(db_host, db_port, username=db_user, password=db_pass, authSource=db_auth_source, authMechanism=db_auth_mechanism, document_class=tinydb_emulated_dict)
			self._db_profile = self._client.hxtool.profile
			self._db_background_processor_credential = self._client.hxtool.background_processor_credential
			self._db_session = self._client.hxtool.session
			self._db_tasks = self._client.hxtool.tasks
			self._db_taskprofiles = self._client.hxtool.taskprofiles
			self._db_alerts = self._client.hxtool.alerts
			self._db_hosts = self._client.hxtool.hosts
			self._db_openioc = self._client.hxtool.openioc
			self._db_scripts = self._client.hxtool.scripts
			self._db_bulk_download = self._client.hxtool.bulk_download
			self._db_file_listing = self._client.hxtool.file_listing
			self._db_multi_file = self._client.hxtool.multi_file
			self._db_stacking = self._client.hxtool.stacking
			self._client.admin.command('ismaster')
			logger.info("MongoDB connection successful")
		except Exception as e:
			logger.error("Unable to connect to MongoDB, error: {}".format(e))
			exit(1)

	def close(self):
		if self._client is not None:
			self._client.close()

	def __exit__(self, exc_type, exc_value, traceback):
		self.close()

	# TODO: Remove after all references are removed
	def mongoStripKeys(self, data):
		return data
		
	def profileCreate(self, hx_name, hx_host, hx_port):
		# Generate a unique profile id
		profile_id = str(secure_uuid4())
		return self._db_profile.insert_one({'profile_id' : profile_id, 'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})

	def profileList(self):
		return list(self._db_profile.find())

	def profileGet(self, profile_id):
		return self._db_profile.find_one( { "profile_id": profile_id } )

	def profileUpdate(self, profile_id, hx_name, hx_host, hx_port):
		return self._db_profile.replace_one({ "profile_id": profile_id }, {'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})

	def profileDelete(self, profile_id):
		self.backgroundProcessorCredentialRemove(profile_id)	
		return self._db_profile.remove( { "profile_id": profile_id } )

	def backgroundProcessorCredentialCreate(self, profile_id, hx_api_username, iv, salt, hx_api_encrypted_password):
		return self._db_background_processor_credential.insert_one({'profile_id' : profile_id, 'hx_api_username' : hx_api_username, 'iv' : iv, 'salt': salt, 'hx_api_encrypted_password' : hx_api_encrypted_password})
		
	def backgroundProcessorCredentialRemove(self, profile_id):
		return self._db_background_processor_credential.remove( { "profile_id": profile_id } )
			
	def backgroundProcessorCredentialGet(self, profile_id):
		return self._db_background_processor_credential.find_one( { "profile_id": profile_id } )

	def alertCreate(self, profile_id, hx_alert_id):
		r = self.alertGet(profile_id, hx_alert_id)
		if not r:
			r = self._db_alerts.insert_one( {'profile_id' : profile_id, 'hx_alert_id' : int(hx_alert_id), 'annotations' : []} )
		return True

	def alertList(self, profile_id):
		return self.mongoStripKeys(list(self._db_alerts.find( { "profile_id": profile_id } )))

	def alertGet(self, profile_id, hx_alert_id):
		return self.mongoStripKeys(self._db_alerts.find_one( { "profile_id": profile_id, "hx_alert_id": int(hx_alert_id) } ))
	
	def alertAddAnnotation(self, profile_id, hx_alert_id, annotation, state, create_user):
		return self._db_alerts.update_one({ "profile_id": profile_id, "hx_alert_id": int(hx_alert_id) }, {"$push": {"annotations": {'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())} }})

	def bulkDownloadCreate(self, profile_id, hostset_name = None, hostset_id = None, task_profile = None):
		r = None
		ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
		r = self._db_bulk_download.insert_one({'profile_id' : profile_id, 
													'hostset_id' : int(hostset_id),
													'hostset_name' : hostset_name,
													'hosts'	: {},
													'task_profile' : task_profile,
													'stopped' : False,
													'complete' : False,
													'create_timestamp' : ts, 
													'update_timestamp' : ts})
		return r.inserted_id
	
	def bulkDownloadGet(self, bulk_download_eid = None, profile_id = None, bulk_acquisition_id = None):
		if bulk_download_eid:
			return self.mongoStripKeys(self._db_bulk_download.find_one( { "_id": ObjectId(bulk_download_eid) } ))
		elif profile_id and bulk_acquisition_id:
			return self.mongoStripKeys(self._db_bulk_download.find_one( { "profile_id": profile_id, "bulk_acquisition_id": bulk_acquisition_id } ))
	
	def bulkDownloadList(self, profile_id):
		return self.mongoStripKeys(list(self._db_bulk_download.find( { "profile_id": profile_id } )))
	
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

		return self._db_bulk_download.update_one( { "_id": ObjectId(bulk_download_eid) }, { "$set": d } )
			
	def bulkDownloadUpdateHost(self, bulk_download_eid, host_id, downloaded = None, hostname = None):
		d = {}
			
		if downloaded is not None:
			d['downloaded'] = downloaded
		if hostname is not None:
			d['hostname'] = hostname

		return self._db_bulk_download.update_one( { "_id": ObjectId(bulk_download_eid) }, { "$set": { "hosts." + host_id: d } } )
	
	def bulkDownloadDeleteHost(self, bulk_download_eid, host_id):
		return self._db_bulk_download.update_one( { "_id": ObjectId(bulk_download_eid) }, { "$unset": { "hosts." + host_id } } )
	
	def bulkDownloadDelete(self, bulk_download_eid):
		return self._db_bulk_download.remove({ "_id": ObjectId(bulk_download_eid) })
	
	def fileListingCreate(self, profile_id, username, bulk_download_eid, path, regex, depth, display_name, api_mode=False):
		ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
		r = self._db_file_listing.insert_one({'profile_id' : profile_id, 
												'display_name': display_name,
												'bulk_download_eid' : str(bulk_download_eid),
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
		return r.inserted_id
		
	def fileListingAddResult(self, profile_id, bulk_download_eid, result):
		return self._db_file_listing.update_one( { "profile_id": profile_id, "bulk_download_eid": str(bulk_download_eid) }, { "$push": { "files": { "$each": result } } } )
	
	def fileListingGetByBulkId(self, profile_id, bulk_download_eid):
		return self._db_file_listing.find_one( { "profile_id": profile_id, "bulk_download_eid": str(bulk_download_eid) } )
	
	def fileListingGetById(self, flid):
		return self.mongoStripKeys(self._db_file_listing.find_one( { "_id": ObjectId(flid) } ))
	
	def fileListingList(self, profile_id):
		res = self.mongoStripKeys(list(self._db_file_listing.find( { "profile_id": profile_id } )))
		return(res)

	def fileListingStop(self, file_listing_id):
		return self._db_file_listing.update_one( { "_id": ObjectId(file_listing_id) }, { "$set": { "stopped": True, "update_timestamp": HXAPI.dt_to_str(datetime.datetime.utcnow()) } } )
	
	def fileListingDelete(self, file_listing_id):
		return self._db_file_listing.remove( { "_id": ObjectId(file_listing_id) } )
	
	def multiFileCreate(self, username, profile_id, display_name=None, file_listing_id=None, api_mode=False):
		ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
		r = self._db_multi_file.insert_one({
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
		return r.inserted_id

	def multiFileAddJob(self, multi_file_id, job):
		return self._db_multi_file.update_one( { "_id": ObjectId(multi_file_id) }, { "$push": { "files": job } } )

	def multiFileList(self, profile_id):
		return self.mongoStripKeys(list(self._db_multi_file.find( { "profile_id": profile_id } )))

	def multiFileGetById(self, multi_file_id):
		return self.mongoStripKeys(self._db_multi_file.find_one( { "_id": ObjectId(multi_file_id) } ))

	def multiFileUpdateFile(self, profile_id, multi_file_id, acquisition_id):
		return self._db_multi_file.update_one( { "_id": ObjectId(multi_file_id) }, { "$set": { "files.$[].acquisition_id": acquisition_id, "files.$[].downloaded": True } } )
																			
	def multiFileStop(self, multi_file_id):
		return self.mongoStripKeys(self._db_multi_file.update_one( { "_id": ObjectId(multi_file_id) }, { "$set": { "stopped": True, "update_timestamp": HXAPI.dt_to_str(datetime.datetime.utcnow()) } } ))
	
	def multiFileDelete(self, multi_file_id):
		return self._db_multi_file.remove( { "_id": ObjectId(multi_file_id) } )
	
	def stackJobCreate(self, profile_id, bulk_download_eid, stack_type):
		ts = HXAPI.dt_to_str(datetime.datetime.utcnow())
		r = self._db_stacking.insert_one({
			'profile_id' : profile_id, 
			'bulk_download_eid' : bulk_download_eid, 
			'stopped' : False,
			'stack_type' : stack_type,
			'hosts' : [],
			'results' : [],
			'last_index' : None,
			'last_groupby' : [],
			'create_timestamp' : ts, 
			'update_timestamp' : ts
		})
		return r.inserted_id
		
	def stackJobGet(self, stack_job_eid = None, profile_id = None, bulk_download_eid = None):
		if stack_job_eid:
			return self._db_stacking.find_one( { "_id": ObjectId(stack_job_eid) } )
		elif profile_id and bulk_download_eid:
			return self._db_stacking.find_one( { "profile_id": profile_id, "bulk_download_eid": ObjectId(bulk_download_eid) } )
	
	def stackJobList(self, profile_id):
		return list(self._db_stacking.find( { "profile_id": profile_id } ))
		
	def stackJobAddHost(self, profile_id, bulk_download_eid, hostname, agent_id):
		return self._db_stacking.update_one( { "profile_id": profile_id, "bulk_download_eid": ObjectId(bulk_download_eid) }, { "$push": { "hosts": {"hostname" : hostname, "agent_id" : agent_id, "processed" : False} } } )
		
	def stackJobAddResult(self, profile_id, bulk_download_eid, hostname, result):
		self._db_stacking.update_one( { "profile_id": profile_id, "bulk_download_eid": ObjectId(bulk_download_eid) }, { "$push": { "results" : { "$each": result }  } } )
		return self._db_stacking.update_one( { "profile_id": profile_id, "bulk_download_eid": ObjectId(bulk_download_eid) }, { "$set": { "hosts.$[].hostname": hostname, "hosts.$[].processed": True } } )
			
	def stackJobStop(self, stack_job_eid):
		return self._db_stacking.update_one( { "_id": ObjectId(stack_job_eid) }, { "$set": { "stopped": True, "update_timestamp": HXAPI.dt_to_str(datetime.datetime.utcnow()) } } )
	
	def stackJobDelete(self, stack_job_eid):
		return self._db_stacking.remove( { "_id": ObjectId(stack_job_eid) } )
	
	def sessionCreate(self, session_id):
		return self._db_session.insert_one({'session_id': session_id, 'session_data': {}, 'update_timestamp'	: HXAPI.dt_to_str(datetime.datetime.utcnow())})
	
	def sessionList(self):
		return self.mongoStripKeys(list(self._db_session.find()))
	
	def sessionGet(self, session_id):
		return self._db_session.find_one( { "session_id": session_id } )
		
	def sessionUpdate(self, session_id, session_data):
		return self._db_session.replace_one({ "session_id": session_id }, { 'session_id': session_id, 'session_data' : dict(session_data), 'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})
		
	def sessionDelete(self, session_id):
		return self._db_session.remove( { "session_id": session_id } )
	
	def scriptCreate(self, scriptname, script, username):
		return self._db_scripts.insert_one({'script_id' : str(secure_uuid4()), 
													'scriptname': str(scriptname), 
													'username' : str(username),
													'script' : str(script), 
													'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
													'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})		

	def scriptList(self):
		return self.mongoStripKeys(list(self._db_scripts.find()))

	def scriptDelete(self, script_id):
		return self._db_scripts.remove( { "script_id": script_id } )

	def scriptGet(self, script_id):
		return self.mongoStripKeys(self._db_scripts.find_one( { "script_id": script_id } ))


	def oiocCreate(self, iocname, ioc, username):
		return self._db_openioc.insert_one({'ioc_id' : str(secure_uuid4()), 
													'iocname': str(iocname), 
													'username' : str(username),
													'ioc' : str(ioc), 
													'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
													'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})		

	def oiocList(self):
		return self.mongoStripKeys(list(self._db_openioc.find()))

	def oiocDelete(self, ioc_id):
		return self._db_openioc.remove( { "ioc_id": ioc_id } )

	def oiocGet(self, ioc_id):
		return self.mongoStripKeys(self._db_openioc.find_one( { "ioc_id": ioc_id } ))

	def taskCreate(self, serialized_task):
		return self._db_tasks.insert_one(serialized_task)
	
	def taskList(self):
		return self.mongoStripKeys(list(self._db_tasks.find()))
	
	def taskGet(self, profile_id, task_id):
		return self._db_tasks.find_one( { "profile_id": profile_id, "task_id": task_id } )
	
	def taskUpdate(self, profile_id, task_id, serialized_task):
		return self._db_tasks.replace_one({ "profile_id": profile_id, "task_id": task_id }, serialized_task)
	
	def taskDelete(self, profile_id, task_id):
		return self._db_tasks.remove( { "profile_id": profile_id, "task_id": task_id } )
			
	def taskProfileAdd(self, name, actor, params):
		return self._db_taskprofiles.insert_one({'taskprofile_id' : str(secure_uuid4()), 
													'name': str(name), 
													'actor' : str(actor),
													'params' : params, 
													'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
													'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})

	def taskProfileList(self):
		return self.mongoStripKeys(list(self._db_taskprofiles.find()))
			
	def taskProfileGet(self, taskprofile_id):
		return self._db_taskprofiles.find_one( { "taskprofile_id": taskprofile_id } )

	def taskProfileDelete(self, taskprofile_id):
		return self._db_taskprofiles.remove({ "taskprofile_id": taskprofile_id })


	def auditCreate(self, profile_id, host_id, hostname, generator, start_time, end_time, results):
		return self._db_audits.insert_one({'profile_id' : profile_id,
												'audit_id'	: str(secure_uuid4()),
												'host_id:'	: host_id,
												'hostname'	: hostname,
												'generator'	: generator,
												'start_time': start_time,
												'end_time'	: end_time,
												'results'	: results})
	
	def auditList(self, profile_id):
		return self.mongoStripKeys(list(self._db_audits.find( { "profile_id": profile_id } )))
	
	def auditGet(self, profile_id, audit_id):
		return self.mongoStripKeys(self._db_audits.find_one( { "profile_id": profile_id, "audit_id": audit_id } ))
			
	def auditDelete(self, profile_id, audit_id):
		return self._db_audits.remove( { "profile_id": profile_id, "audit_id": audit_id } )