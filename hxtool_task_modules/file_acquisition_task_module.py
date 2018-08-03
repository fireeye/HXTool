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

	@staticmethod
	def input_args():
		return [
			{
				'name' : 'multi_file_eid',
				'type' : int,
				'required' : True,
				'user_supplied' : False,
				'description' : "The document ID of the multi-file download job."
			},
			{
				'name' : 'file_acquisition_id',
				'type' : int,
				'required' : True,
				'user_supplied' : False,
				'description' : "The ID assigned to the file acquisition by the controller."
			},
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host name of this file acquisition package."
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	def run(self, multi_file_eid = None, file_acquisition_id = None, host_name = None):
		ret = False
		result = {}
		try:
			hx_api_object = self.get_task_api_object()	
			if hx_api_object and hx_api_object.restIsSessionValid():
				self.logger.debug("Processing multi file acquisition job: {0}.".format(multi_file_eid))
				download_directory = make_download_directory(hx_api_object.hx_host, multi_file_eid, job_type = 'multi_file')
				(ret, response_code, response_data) = hx_api_object.restFileAcquisitionById(file_acquisition_id)
				if ret and response_data and response_data['data']['state'] == "COMPLETE" and response_data['data']['url']:
					self.logger.debug("Processing multi file acquisition host: {0}".format(host_name))
					full_path = os.path.join(download_directory, get_download_filename(host_name, file_acquisition_id))				
					(ret, response_code, response_data) = hx_api_object.restDownloadFile('{}.zip'.format(response_data['data']['url']), full_path)
					if ret:
						hxtool_global.hxtool_db.multiFileUpdateFile(self.parent_task.profile_id, multi_file_eid, file_acquisition_id)
						self.logger.info("File Acquisition download complete. Acquisition ID: {0}, Batch: {1}".format(file_acquisition_id, multi_file_eid))
				elif response_code == 404:
					self.logger.error("File acquisition ID: {} not found on the controller.".format(file_acquisition_id))
					self.parent_task.stop()
				else:
					self.logger.debug("Deferring file acquisition for: {}".format(host_name))
					self.parent_task.defer()
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))
		except Exception as e:
			self.logger.error(e)
		finally:
			return(ret, result)