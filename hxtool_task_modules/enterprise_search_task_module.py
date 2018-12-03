#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *
from hx_lib import *

class enterprise_search_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{
				'name' : 'script',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The OpenIOC 1.1 formatted script to utilize."
			},
			{
				'name' : 'hostset_id',
				'type' : int,
				'required' : True,
				'user_supplied' : True,
				'description' : "The ID of the host set to execute the script against."
			},
			{
				'name' : 'ignore_unsupported_items',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Specifies whether to instruct the HX controller to ignore unsupported items in the script. Defaults to False"
			},
			{
				'name' : 'skip_base64',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Specifies whether the contents of the script argument are already base64 encoded. Defaults to False"
			},
			{
				'name' : 'displayname',
				'type' : str,
				'required' : False,
				'user_supplied' : True,
				'description' : "Specifies the display name of the search. Defaults to False"
			}
		]
		
	@staticmethod
	def output_args():
		return [
			{
				'name' : 'enterprise_search_id',
				'type' : int,
				'required' : True,
				'description' : "The Enterprise Search ID assigned to the search job by the controller."
			}
		]
	
	def run(self, script = None, hostset_id = None, ignore_unsupported_items = False, skip_base64 = False, displayname = False):
		ret = False
		result = {}
		if script:
			hx_api_object = self.get_task_api_object()	
			if hx_api_object and hx_api_object.restIsSessionValid():
				(ret, response_code, response_data) = hx_api_object.restSubmitSweep(script, hostset_id, ignore_unsupported_items = ignore_unsupported_items, skip_base64 = skip_base64, displayname = displayname)
				if ret:
					result['enterprise_search_id'] = response_data['data']['_id']
					self.parent_task.name = "Enterprise Search ID: {}".format(response_data['data']['_id'])
					self.logger.info("Enterprise Search ID: {} successfully submitted.".format(result['enterprise_search_id']))
				else:
					self.logger.error("Enterprise Search submission failed. Response code: {}, response data: {}".format(response_code, response_data))
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))	
		return(ret, result)