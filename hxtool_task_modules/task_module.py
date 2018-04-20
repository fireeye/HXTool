#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from hx_lib import *	
	
class task_module(object):
	def __init__(self, parent_task):
		self.parent_task = parent_task
		
	def get_task_api_object(self):
		if self.parent_task.profile_id in hxtool_global.task_hx_api_sessions:
			return hxtool_global.task_hx_api_sessions[self.parent_task.profile_id]
		return None
	
	# Note: function return must be a tuple of (boolean, result)
	def run(self):
		raise NotImplementedError("You must override run() in your task modules.")