#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import hxtool_global
from .task_module import *
from hxtool_data_models import *
from hx_audit import *

class file_listing_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{
				'name' : 'bulk_download_eid',
				'type' : int,
				'required' : True,
				'user_supplied' : False,
				'description' : "The document ID of the bulk download job."
			},
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host name of this bulk acquisition package."
			},
			{
				'name' : 'bulk_download_path',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The fully qualified path to the bulk acquisition package."
			},
			{
				'name' : 'delete_bulk_download',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Flag whether to delete the bulk acquisition package locally once complete. Defaults to False"
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	
	def run(self, bulk_download_eid = None, host_name = None, bulk_download_path = None, delete_bulk_download = False):
		ret = False
		result = {}
		try:
			file_listing = hxtool_global.hxtool_db.fileListingGetByBulkId(self.parent_task.profile_id, bulk_download_eid)
			generator = 'files-raw'
			if file_listing and 'api_mode' in file_listing['cfg'] and file_listing['cfg']['api_mode']:
				generator = 'files-api'
			with AuditPackage(bulk_download_path) as audit_pkg:
				audit_data = audit_pkg.get_audit(generator = generator, open_only=True)
				if audit_data:
					files = get_audit_records(audit_data, generator, 'FileItem', hostname=host_name)
					if files:
						hxtool_global.hxtool_db.fileListingAddResult(self.parent_task.profile_id, bulk_download_eid, files)
						self.logger.debug("File Listing added to the database. bulk job: {0} host: {1}".format(bulk_download_eid, host_name))
						ret = True
					else:
						self.logger.warn("File Listing: No audit data for {} from bulk download job {}".format(host_name, bulk_download_eid))
					audit_data.close()
					
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
		finally:
			return(ret, result)