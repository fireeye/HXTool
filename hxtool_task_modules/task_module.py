#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from hx_lib import *	
	
class task_module(object):
	def __init__(self, parent_task):
		self.parent_task = parent_task
		self.logger = parent_task.logger
	
	def get_task_api_object(self):
		if self.parent_task.profile_id in hxtool_global.task_hx_api_sessions:
			return hxtool_global.task_hx_api_sessions[self.parent_task.profile_id]
		return None
		
	def run_args(self):
		raise NotImplementedError("You must define a list of arguments that your module's run() function requires!")
	
	# Note: function return must be a tuple of (boolean, result)
	def run(self, **kwargs):
		raise NotImplementedError("You must override run() in your task module.")
		
	# Used by the task scheduler to signal that we are an HXTool Task Module
	@staticmethod
	def hxtool_task_module():
		return True