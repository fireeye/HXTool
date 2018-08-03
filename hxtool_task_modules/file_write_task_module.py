#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

import hxtool_global
from .task_module import *
from hx_audit import *

class file_write_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host name belonging to the bulk acquisition package."
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
			},
			{
				'name' : 'file_name',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The fully qualified path of the file to write to."
			},
			{
				'name' : 'file_append',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Append to the file rather than overwriting it. Defaults to True"
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	def run(self, host_name = None, bulk_download_path = None, delete_bulk_download = False, file_name = None, file_append = True):
		ret = False
		result = {}
		try:
			if bulk_download_path:
				audit_objects = []
				with AuditPackage(bulk_download_path) as audit_package:
					for audit in audit_package.audits:
						audit_object = audit_package.audit_to_dict(audit)
						if audit_object:
							audit_objects.append(audit_object)
				if len(audit_objects) > 0:
					file_mode = 'a'
					if not file_append:
						file_mode = 'w'
					with open(file_name, file_mode) as f:
						json.dump(f, audit_objects, sort_keys = False, indent = 4)
					f.close()			
					ret = True
				else:
					self.logger.warn("Streaming: No audit data for {} from bulk acquisition {}".format(host_name, bulk_acquisition_id))
												
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
				
			else:
				self.logger.error("bulk_download_path is empty!")
		except Exception as e:
			self.logger.error(e)
		finally:	
			return(ret, result)