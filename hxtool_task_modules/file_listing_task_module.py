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
		self.logger = parent_task.logger
	
	def run(self, bulk_download_id, hostname, bulk_download_path = None, delete_bulk_download = False):
		ret = False
		result = None
		try:
			file_listing = hxtool_global.hxtool_db.fileListingGetByBulkId(self.parent_task.profile_id, bulk_download_id)
			generator = 'w32rawfiles'
			if file_listing and 'api_mode' in file_listing['cfg'] and file_listing['cfg']['api_mode']:
				generator = 'w32apifiles'
			with AuditPackage(bulk_download_path) as audit_pkg:
				audit_data = audit_pkg.get_audit(generator = generator)
				if audit_data:
					files = get_audit_records(audit_data, generator, 'FileItem', hostname=hostname)
					if files:
						hxtool_global.hxtool_db.fileListingAddResult(self.parent_task.profile_id, bulk_download_id, files)
						self.logger.debug("File Listing added to the database. bulk job: {0} host: {1}".format(bulk_download_id, hostname))
						ret = True
					else:
						self.logger.warn("File Listing: No audit data for {} from bulk acquisition {}".format(hostname, bulk_download_id))
		except Exception as e:
			self.logger.error(e)
		finally:
			return(ret, result)