#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hxtool_db import hxtool_db

try:
	from pymongo import MongoClient
except ImportError:
	print("HXTool is configured to use MongoDB. Please install the 'pymongo' Python module")
	exit(1)

import datetime
import json
import shlex
import re
import hxtool_vars
import hxtool_logging
from hx_lib import HXAPI
from hxtool_util import secure_uuid4
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

class hxtool_mongodb(hxtool_db):
	def __init__(self, db_host, db_port, db_user, db_pass, db_auth_source, db_auth_mechanism, db_name="hxtool"):
		try:
			self._client = MongoClient(db_host, db_port, username=db_user, password=db_pass, authSource=db_auth_source, authMechanism=db_auth_mechanism, document_class=tinydb_emulated_dict)
			self._db_profile = self._client[db_name].profile
			self._db_background_processor_credential = self._client[db_name].background_processor_credential
			self._db_session = self._client[db_name].session
			self._db_tasks = self._client[db_name].tasks
			self._db_taskprofiles = self._client[db_name].taskprofiles
			self._db_alerts = self._client[db_name].alerts
			self._db_hosts = self._client[db_name].hosts
			self._db_openioc = self._client[db_name].openioc
			self._db_scripts = self._client[db_name].scripts
			self._db_bulk_download = self._client[db_name].bulk_download
			self._db_file_listing = self._client[db_name].file_listing
			self._db_multi_file = self._client[db_name].multi_file
			self._db_stacking = self._client[db_name].stacking
			self._db_audits = self._client[db_name].audits
			self._client.admin.command('ismaster')
			logger.info("MongoDB connection successful")
		except Exception as e:
			logger.error("Unable to connect to MongoDB, error: {}".format(e))
			exit(1)
		
		# Ensure that the text wildcard index is in place
		self._db_audits.create_index([("$**","text")])
	
	@property
	def database_engine(self):
		return "mongodb"

	def close(self):
		if self._client is not None:
			self._client.close()

	def __exit__(self, exc_type, exc_value, traceback):
		self.close()

	def auditInsert(self, auditdata):
		return self._db_audits.insert_one(auditdata)

	def auditRemove(self, myid):
		return self._db_audits.remove({"bulk_acquisition_id": int(myid)})

	def auditQueryAggregate(self, query, qlimit = 1000):
		query.append({ "$limit": qlimit })
		#print(query)
		return self._db_audits.aggregate(query)

	def auditQuery(self, query, sort = None, qlimit = 1000):
		#print(query)
		if sort:
			return self._db_audits.find(query).sort(sort['sortkey'], sort['operator']).limit(qlimit)
		else:
			return self._db_audits.find(query).limit(qlimit)

	def auditGetCollections(self):
		pipeline = [{'$group': {'count': {'$sum': 1}, '_id': {'bulk_acquisition_id': '$bulk_acquisition_id'}}}, {'$limit': 1000}]
		return self._db_audits.aggregate(pipeline)
		
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
		return list(self._db_alerts.find( { "profile_id": profile_id } ))

	def alertGet(self, profile_id, hx_alert_id):
		return self._db_alerts.find_one( { "profile_id": profile_id, "hx_alert_id": int(hx_alert_id) } )
	
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
			return self._db_bulk_download.find_one( { "_id": ObjectId(bulk_download_eid) } )
		elif profile_id and bulk_acquisition_id:
			return self._db_bulk_download.find_one( { "profile_id": profile_id, "bulk_acquisition_id": bulk_acquisition_id } )
	
	def bulkDownloadList(self, profile_id):
		return list(self._db_bulk_download.find( { "profile_id": profile_id } ))
	
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
		return self._db_file_listing.find_one( { "_id": ObjectId(flid) } )
	
	def fileListingList(self, profile_id):
		return list(self._db_file_listing.find( { "profile_id": profile_id } ))
		
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
		return list(self._db_multi_file.find( { "profile_id": profile_id } ))

	def multiFileGetById(self, multi_file_id):
		return self._db_multi_file.find_one( { "_id": ObjectId(multi_file_id) } )

	def multiFileUpdateFile(self, profile_id, multi_file_id, acquisition_id):
		return self._db_multi_file.update_one( { "_id": ObjectId(multi_file_id) }, { "$set": { "files.$[].acquisition_id": acquisition_id, "files.$[].downloaded": True } } )
																			
	def multiFileStop(self, multi_file_id):
		return self._db_multi_file.update_one( { "_id": ObjectId(multi_file_id) }, { "$set": { "stopped": True, "update_timestamp": HXAPI.dt_to_str(datetime.datetime.utcnow()) } } )
	
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
		return list(self._db_session.find())
	
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
		return list(self._db_scripts.find())

	def scriptDelete(self, script_id):
		return self._db_scripts.remove( { "script_id": script_id } )

	def scriptGet(self, script_id):
		return self._db_scripts.find_one( { "script_id": script_id } )


	def oiocCreate(self, iocname, ioc, username):
		return self._db_openioc.insert_one({'ioc_id' : str(secure_uuid4()), 
													'iocname': str(iocname), 
													'username' : str(username),
													'ioc' : str(ioc), 
													'create_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow()), 
													'update_timestamp' : HXAPI.dt_to_str(datetime.datetime.utcnow())})		

	def oiocList(self):
		return list(self._db_openioc.find())

	def oiocDelete(self, ioc_id):
		return self._db_openioc.remove( { "ioc_id": ioc_id } )

	def oiocGet(self, ioc_id):
		return self._db_openioc.find_one( { "ioc_id": ioc_id } )

	def taskCreate(self, serialized_task):
		return self._db_tasks.insert_one(serialized_task)
	
	def taskList(self):
		return list(self._db_tasks.find())
	
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
		return list(self._db_taskprofiles.find())
			
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
		return list(self._db_audits.find( { "profile_id": profile_id } ))
	
	def auditGet(self, profile_id, audit_id):
		return self._db_audits.find_one( { "profile_id": profile_id, "audit_id": audit_id } )
			
	def auditDelete(self, profile_id, audit_id):
		return self._db_audits.remove( { "profile_id": profile_id, "audit_id": audit_id } )

	def queryParse(self, myQuery):

		myQueryParts = myQuery.split("|")

		mstr = myQueryParts[0]

		# Remove first whitespace
		if mstr.startswith(" "): mstr = mstr[1:]

		# Get the full text search
		if " " in mstr:
			fsearch = mstr[:mstr.index(" ")]
		else:
			fsearch = mstr

		mysearch_dict = {}
		mysearch_dict['type'] = "find"

		mstr_parts = shlex.split(mstr)

		ftext = False
		for p in mstr_parts:
			if not any(l in p for l in ["=", ":", "<", ">"]):
				ftext = True

		if mstr == "":
			# Get all events if search is empty
			mysearch_dict['query'] = {}
		else:
			if ftext == True:
				# There is a full text query
				mysearch_dict['query'] = { "$text": { "$search": fsearch } }
			else:
				mysearch_dict['query'] = {}

		# Find search filters
		for part in mstr_parts:

			myoperator = False
			for char in part:
				if char in ['=', ":", "<", ">"]:
					myoperator = char
					break

			if myoperator == ":":
				ppart = part.split(":", 1)
				if len(ppart) > 1:
					mysearch_dict['query'][ppart[0]] = { "$regex": ".*" + re.escape(ppart[1]) + ".*" }
			elif myoperator == "=":
				ppart = part.split("=", 1)
				if len(ppart) > 1:
					if ppart[1].startswith("(") and ppart[1].endswith(")"):
						ppart[1] = int(ppart[1].replace("(","").replace(")",""))
					mysearch_dict['query'][ppart[0]] = { "$eq": ppart[1] }
			elif myoperator == ">":
				ppart = part.split(">", 1)
				if len(ppart) > 1:
					if ppart[1].startswith("(") and ppart[1].endswith(")"):
						ppart[1] = int(ppart[1].replace("(","").replace(")",""))
					mysearch_dict['query'][ppart[0]] = { "$gte": ppart[1] }
			elif myoperator == "<":
				ppart = part.split("<", 1)
				if len(ppart) > 1:
					if ppart[1].startswith("(") and ppart[1].endswith(")"):
						ppart[1] = int(ppart[1].replace("(","").replace(")",""))
					mysearch_dict['query'][ppart[0]] = { "$lte": ppart[1] }

		if len(myQueryParts) > 1:
			
			for part in myQueryParts:
				if part.startswith(" "): part = part[1:]

				if part.startswith("groupby"):
					#Aggregation pipeline
					mysearch_dict['type'] = "aggregate"
					mygroup = {"count": {"$sum": 1}}
					ppart = part.replace("groupby", "")
					if ppart.startswith(" "): ppart = ppart[1:]
					ppart = ppart.split(",")

					mygroup['_id'] = {}
					for myGroupPart in ppart:
						myGroupPart = myGroupPart.replace(" ", "")
						mygroup['_id'][myGroupPart.replace(".", "/")] = "$" + myGroupPart

					myMatch = mysearch_dict['query']
					mysearch_dict['query'] = [{ "$match": myMatch }, { "$group": mygroup }]

				if part.startswith("sort"):
					if mysearch_dict['type'] == "aggregate":
						part = part.replace("sort", "")
						if part.startswith(" "): part = part[1:]

						if ":" in part:
							parts = part.split(":")
							if parts[1] == "desc":
								sortq = { "$sort": { parts[0]: -1 }}
							elif parts[1] == "asc":
								sortq = { "$sort": { parts[0]: 1 }}
							else:
								sortq = { "$sort": { parts[0]: -1 }}
						else:
							sortq = { "$sort": { part: -1 }}

						mysearch_dict['query'].append(sortq)
					elif mysearch_dict['type'] == "find":
						part = part.replace("sort", "")
						if part.startswith(" "): part = part[1:]

						if ":" in part:
							parts = part.split(":")
							if parts[1] == "desc":
								sortq = { "sortkey": parts[0], "operator": -1 }
							elif parts[1] == "asc":
								sortq = { "sortkey": parts[0], "operator": 1 }
							else:
								sortq = { "sortkey": parts[0], "operator": -1 }
						else:
							sortq = { "sortkey": part, "operator": -1 }

						mysearch_dict['sort'] = sortq


		return(mysearch_dict)