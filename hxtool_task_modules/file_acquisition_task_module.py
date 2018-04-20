#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time

import hxtool_global
from .task_module import *
from hxtool_util import *

class file_acquisition_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
		self.logger = parent_task.logger
	
	def run(self, mf_job_id, file_acquisition_id, hostname):
		ret = False
		result = None
		try:
			hx_api_object = self.get_task_api_object()	
			if hx_api_object and hx_api_object.restIsSessionValid():
				self.logger.debug("Processing multi file acquisition job: {0}.".format(mf_job_id))
				download_directory = make_download_directory(hx_api_object.hx_host, mf_job_id, job_type = 'multi_file')
				(ret, response_code, response_data) = hx_api_object.restFileAcquisitionById(file_acquisition_id)
				if ret and response_data and response_data['data']['state'] == "COMPLETE" and response_data['data']['url']:
					self.logger.debug("Processing multi file acquisition host: {0}".format(hostname))
					full_path = os.path.join(download_directory, get_download_filename(hostname, file_acquisition_id))				
					(ret, response_code, response_data) = hx_api_object.restDownloadFile('{}.zip'.format(response_data['data']['url']), full_path)
					if ret:
						hxtool_global.hxtool_db.multiFileUpdateFile(self.parent_task.profile_id, mf_job_id, file_acquisition_id)
						self.logger.info("File Acquisition download complete. Acquisition ID: {0}, Batch: {1}".format(file_acquisition_id, mf_job_id))
				else:
					self.logger.debug("Deferring file acquisition for: {}".format(hostname))
					self.parent_task.defer()
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))
		except Exception as e:
			self.logger.error(e)
		finally:
			return(ret, result)