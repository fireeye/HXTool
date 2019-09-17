#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This is a system task module that performs the API logins needed by the task scheduler.

import hxtool_global
from .task_module import *
from hx_lib import *

class task_api_session_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{
				'name' : 'profile_id',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The profile ID of the HXTool profile."
			},
			{
				'name' : 'username',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The HX API username."
			},
			{
				'name' : 'password',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The HX API password."
			}
		]
		
	@staticmethod
	def output_args():
		return []
	
	def run(self, profile_id = None, username = None, password = None):
		ret = False
		if self.get_task_api_object() is not None:
			(ret, response_code, response_data) = self.get_task_api_object().restLogin(username, password, auto_renew_token = True)
			if ret:
				self.logger.info("Successfully initialized task API session for host {} ({})".format(self.get_task_api_object().hx_host, profile_id))
			else:
				self.logger.warn("Failed to initialize task API session for host {} ({})".format(self.get_task_api_object().hx_host, profile_id))
				# TODO: need a better way to handle this
				del hxtool_global.hxtool_scheduler.task_hx_api_sessions[profile_id]
			password = None
		return ret