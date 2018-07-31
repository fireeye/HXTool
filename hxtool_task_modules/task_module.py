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