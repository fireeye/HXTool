#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *
from hx_lib import *

class enterprise_search_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
		self.logger = parent_task.logger

	def run(self, script, hostset, skip_base64 = False):
		ret = False
		if script:
			hx_api_object = self.get_task_api_object()	
			if hx_api_object and hx_api_object.restIsSessionValid():
				(ret, response_code, response_data) = hx_api_object.restSubmitSweep(script, hostset, skip_base64 = skip_base64)
				if ret:
					self.logger.debug("Enterprise Search successfully submitted.")
				else:
					self.logger.debug("Enterprise Search submission failed. Response code: {}, response data: {}".format(response_code, response_data))
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))	
		return(ret, None)