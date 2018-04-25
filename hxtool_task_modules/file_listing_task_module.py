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
	def run_args():
		return [
			'bulk_acquisition_id',
			'host_name',
			'bulk_download_path',
			'delete_bulk_download'
		]
	
	def run(self, bulk_acquisition_id = None, host_name = None, bulk_download_path = None, delete_bulk_download = False):
		ret = False
		result = None
		try:
			file_listing = hxtool_global.hxtool_db.fileListingGetByBulkId(self.parent_task.profile_id, bulk_acquisition_id)
			generator = 'w32rawfiles'
			if file_listing and 'api_mode' in file_listing['cfg'] and file_listing['cfg']['api_mode']:
				generator = 'w32apifiles'
			with AuditPackage(bulk_download_path) as audit_pkg:
				audit_data = audit_pkg.get_audit(generator = generator)
				if audit_data:
					files = get_audit_records(audit_data, generator, 'FileItem', hostname=host_name)
					if files:
						hxtool_global.hxtool_db.fileListingAddResult(self.parent_task.profile_id, bulk_acquisition_id, files)
						self.logger.debug("File Listing added to the database. bulk job: {0} host: {1}".format(bulk_acquisition_id, host_name))
						ret = True
					else:
						self.logger.warn("File Listing: No audit data for {} from bulk acquisition {}".format(host_name, bulk_acquisition_id))
		except Exception as e:
			self.logger.error(e)
		finally:
			return(ret, result)