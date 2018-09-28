#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

import hxtool_global
from .task_module import *
from hx_audit import *
from hxtool_util import *

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
				'name' : 'agent_id',
				'type' : str,
				'required' : False,
				'user_supplied' : False,
				'description' : "The host/agent ID of the bulk acquisition to download."
			},
			{
				'name' : 'bulk_download_path',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The fully qualified path to the bulk acquisition package."
			},
			{
				'name' : 'batch_mode',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Flag whether to batch each audit as single JSON object versus sending each record as a separate object. Defaults to False"
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
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	def run(self, host_name = None, agent_id = None, bulk_download_path = None, batch_mode = False, delete_bulk_download = False, file_name = None):
		ret = False
		result = {}
		try:
			if bulk_download_path:
				# TODO: this module is not thread-safe, and will result in file locking issues. Ultimately, this should be converted to
				# utilizing the Python rotating log handler.  
				with TemporaryFileLock(os.path.dirname(file_name)):
					with open(file_name, 'a') as f:
						for audit_object in self.yield_audit_results(bulk_download_path, batch_mode, host_name, agent_id):
							json.dump(audit_object, f, sort_keys = False)
							f.write('\n')
						f.close()			
				ret = True								
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
				
			else:
				self.logger.error("bulk_download_path is empty!")
		except Exception as e:
			self.logger.error(e)
		finally:	
			return(ret, result)