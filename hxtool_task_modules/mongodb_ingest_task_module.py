#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

import hxtool_global
from .task_module import *
from hx_audit import *
from hxtool_util import *

class mongodb_ingest_task_module(task_module):
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
				'name' : 'bulk_acquisition_id',
				'type' : int,
				'required' : True,
				'description' : "The bulk acquisition ID assigned to the bulk acquisition job by the controller."
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
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	def run(self, host_name = None, agent_id = None, bulk_download_path = None, bulk_acquisition_id = None, batch_mode = False, delete_bulk_download = False):
		ret = False
		result = {}
		try:
			if bulk_download_path:
				for audit_object in self.yield_audit_results(bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = bulk_acquisition_id):
					hxtool_global.hxtool_db.auditInsert(audit_object)
				ret = True								
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
				
			else:
				self.logger.error("bulk_download_path is empty!")
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
		finally:	
			return(ret, result)