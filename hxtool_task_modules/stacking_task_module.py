#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import hxtool_global
from .task_module import *
from hxtool_data_models import *
from hx_audit import *

class stacking_task_module(task_module):
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
		try:
			ret = False
			if bulk_download_path:
				stack_job = hxtool_global.hxtool_db.stackJobGet(profile_id = self.parent_task.profile_id, bulk_download_eid = bulk_download_eid)
				stack_model = hxtool_data_models(stack_job['stack_type']).stack_type
				with AuditPackage(bulk_download_path) as audit_pkg:
					audit_data = audit_pkg.get_audit(generator=stack_model['audit_module'], open_only=True)
					if audit_data:
						records = get_audit_records(audit_data, stack_model['audit_module'], stack_model['item_name'], fields=stack_model['fields'], post_process=stack_model['post_process'], hostname=host_name)
						if records:
							hxtool_global.hxtool_db.stackJobAddResult(self.parent_task.profile_id, bulk_download_eid, host_name, records)
							self.logger.debug("Stacking records added to the database for host {}".format(host_name))
							ret = True
						else:
							self.logger.warn("Stacking: No audit data for {}".format(host_name))
									
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
					
			else:
				self.logger.error("bulk_download_path is empty!")
				
			return(ret, None)
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
			return(False, None)