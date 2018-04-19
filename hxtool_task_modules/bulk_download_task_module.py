#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import hxtool_global
from .task_module import *
from hxtool_util import *

class bulk_download_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
		self.logger = parent_task.logger

	def run(self, poll_interval, bulk_download_id, host_id, host_name):
		result = {}
		ret = False
		if hxtool_global.hxtool_db.bulkDownloadGet(self.parent_task.profile_id, bulk_download_id)['stopped'] == False:			
			hx_api_object = self.get_task_api_object()	
			if hx_api_object and hx_api_object.restIsSessionValid():
				
				bulk_acquisition_started = False
				while bulk_acquisition_started == False:
					(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(bulk_download_id)
					bulk_acquisition_started = (response_data['data']['state'] == 'RUNNING')
					self.logger.debug("Waiting for bulk acquisition {} to start.".format(bulk_download_id))
					time.sleep(5)
				
				should_stop = False
				while should_stop == False:					
					(ret, response_code, response_data) = hx_api_object.restGetBulkHost(bulk_download_id, host_id)
					if ret:
						if response_data['data']['state'] == "COMPLETE" and response_data['data']['result']:
							self.logger.debug("Processing bulk download for host: {0}".format(host_name))
							download_directory = make_download_directory(hx_api_object.hx_host, bulk_download_id)
							full_path = os.path.join(download_directory, get_download_filename(host_name, host_id))
							(ret, response_code, response_data) = hx_api_object.restDownloadFile(response_data['data']['result']['url'], full_path)
							if ret:
								hxtool_global.hxtool_db.bulkDownloadUpdateHost(self.parent_task.profile_id, bulk_download_id, host_id)
								self.logger.debug("Bulk download for host {} successfully downloaded to {}".format(host_name, full_path))
								result['bulk_download_path'] = full_path
							should_stop = True
						elif response_data['data']['state'] == 'FAILED':
							should_stop = True
							ret = False
						elif response_data['data']['state'] in {'CANCELLED', 'ABORTED'}:
							should_stop = True
							self.parent_task.stop()
							ret = False
						else:
							self.logger.debug("Sleeping for {} seconds".format(poll_interval))						
							time.sleep(poll_interval)
					else:
						self.logger.warn("Failed to get host: {} for bulk acquisition: {}, response code: {}, response data: {}".format(host_name, bulk_download_id, response_code, response_data))
						should_stop = True
						ret = False
			else:
				self.logger.warn("No task API session for profile: {}".format(self.profile_id))
		else:
			self.logger.info("Bulk download {} is stopped.".format(bulk_download_id))
			self.parent_task.stop()
			
		return(ret, result)		
