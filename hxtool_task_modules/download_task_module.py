#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *

class download_task_module(task_module):
	def __init__(self, profile_id):
		super(download_task_module, self).__init__(profile_id)
		
	def run(self, download_url, destination_path, bulk_download_id, host_id):
		ret = False
		hx_api_object = self.get_task_api_object()
		if hx_api_object and hx_api_object.restIsSessionValid():
			(ret, response_code, response_data) = hx_api_object.restDownloadFile(download_url, destination_path)
			if ret:
				self.logger.debug("Download of {} to {} successful.".format(download_url, destination_path))
				hxtool_global.hxtool_db.bulkDownloadUpdateHost(self.profile_id, bulk_download_id, host_id)
		else:
			self.logger.warn("No task API session for profile: {}".format(self.profile_id))
		return ret	
