#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from hx_lib import *
from hx_audit import *
from hxtool_util import *	
	
class task_module(object):
	def __init__(self, parent_task):
		self.parent_task = parent_task
		self.logger = hxtool_global.get_logger(__name__)
		self.enabled = True
	
	def get_task_api_object(self):
		if self.parent_task.profile_id in hxtool_global.task_hx_api_sessions:
			if hxtool_global.task_hx_api_sessions[self.parent_task.profile_id].restIsSessionValid():
				return hxtool_global.task_hx_api_sessions[self.parent_task.profile_id]
		return None
	
	def yield_audit_results(self, bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = None):
		hx_host = None
		api_object = self.get_task_api_object()
		if api_object:
			hx_host = api_object.hx_host
		api_object = None
		
		with AuditPackage(bulk_download_path) as audit_package:
			for audit in audit_package.audits:
				for audit_object in audit_package.audit_to_dict(audit, host_name, agent_id = agent_id, batch_mode = batch_mode):
					audit_object.update({
						'hx_host' : hx_host,
						'bulk_acquisition_id' : bulk_acquisition_id
					})
					yield audit_object
			
	# Input and output args are a list of dictionary objects containing the following five keys: name, type, required user_supplied, and description 
	# these define the modules inputs and outputs, for example:
	# @staticmethod
	# def input_args():
	# 	return [ {'name' : 'foo', 'type' : str, 'required' : True, 'user_supplied' : True, 'description' : "Foo argument"} ]
	# 
	@staticmethod
	def input_args():
		raise NotImplementedError("You must define a list of arguments that your module's run() function requires!")
	
	@staticmethod
	def output_args():
		raise NotImplementedError("You must define a list of arguments that your module will output!")
	
	# Note: function return must be a tuple of (boolean, result)
	def run(self, **kwargs):
		raise NotImplementedError("You must override run() in your task module.")
		
	# Used by the task scheduler to signal that we are an HXTool Task Module
	@staticmethod
	def hxtool_task_module():
		return True