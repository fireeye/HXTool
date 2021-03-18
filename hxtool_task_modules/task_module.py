#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_logging
from hx_lib import *
from hx_audit import *
from hxtool_util import *

class task_module(object):
	MAX_RETRY = 10
	
	# TODO: parent_task should probably be renamed to just task, as modules are associated with tasks
	# and this confuses the parent/child task relationship.
	def __init__(self, task):
		self.parent_task = task
		self.logger = hxtool_logging.getLogger(__name__)
		self.enabled = True
		self.retry_count = 0
	
	def get_task_api_object(self):
		s = self.parent_task.scheduler.task_hx_api_sessions.get(self.parent_task.profile_id, None)
		if s is not None and s.restIsSessionValid():
			return s
		else:
			self.logger.error("There is no valid background task API session for profile {}".format(self.parent_task.profile_id))
			return None
		
	def can_retry(self, err):
		return('connection' in str(type(err)).lower() and self.retry_count < task_module.MAX_RETRY)
	
	def yield_audit_results(self, bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = None):
		hx_host = None
		api_object = self.get_task_api_object()
		if api_object:
			hx_host = api_object.hx_host
		api_object = None
		
		with AuditPackage(bulk_download_path) as audit_package:
			for audit in audit_package.audits:
				try:
					for audit_object in audit_package.audit_to_dict(audit, host_name, agent_id = agent_id, batch_mode = batch_mode):
						audit_object.update({
							'hx_host' : hx_host,
							'bulk_acquisition_id' : bulk_acquisition_id
						})
						yield audit_object
				except EmptyAuditException as e:
					self.logger.warning(e)
			
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