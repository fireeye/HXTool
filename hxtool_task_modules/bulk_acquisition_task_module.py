#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *
from hx_lib import *
from hxtool_util import set_time_macros

class bulk_acquisition_task_module(task_module):
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
				'name' : 'comment',
				'type' : str,
				'required' : False,
				'user_supplied' : True,
				'description' : "A name/comment to associate with this bulk acquisition."
			},
			{
				'name' : 'skip_base64',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Specifies whether the contents of the script argument are already base64 encoded. Defaults to False"
			},
			{
				'name' : 'download',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Specifies whether we should update a bulk download job after this bulk acquisition is submitted."
			},
			{
				'name' : 'bulk_download_eid',
				'type' : int,
				'required' : False,
				'user_supplied' : False,
				'description' : "The document ID of the bulk download job."
			}
		]
		
	@staticmethod
	def output_args():
		return [
			{
				'name' : 'bulk_download_eid',
				'type' : int,
				'required' : False,
				'description' : "The document ID of the bulk download job."
			},
			{
				'name' : 'bulk_acquisition_id',
				'type' : int,
				'required' : True,
				'description' : "The bulk acquisition ID assigned to the bulk acquisition job by the controller."
			}
		]
		
	def run(self, script = None, hostset_id = None, comment = None, skip_base64 = False, download = False, bulk_download_eid = None):
		ret = False
		if script:
			result = {}
			hx_api_object = self.get_task_api_object()	
			if hx_api_object:
				if skip_base64:
					script = HXAPI.b64(script, decode = True, decode_string = True)
				script, has_macros = set_time_macros(script)
				if not has_macros and self.parent_task.last_run and self.parent_task.stored_result.get('bulk_acquisition_id', 0) > 1:
					(ret, response_code, response_data) = hx_api_object.restRefreshBulkAcq(self.parent_task.stored_result['bulk_acquisition_id'])
				else:
					# If there's an old job, delete it if it complete
					if self.parent_task.last_run and self.parent_task.stored_result.get('bulk_acquisition_id', 0) > 1:
						self.logger.info("Previous bulk acquisition job {} found for this scheduled task. Checking completion status to determine if it can be deleted.".format(self.parent_task.stored_result['bulk_acquisition_id']))
						(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(self.parent_task.stored_result['bulk_acquisition_id'])
						if ret:
							total_incomplete_hosts = sum(response_data['data']['stats']['running_state'][_] for _ in response_data['data']['stats']['running_state'] if _ != "COMPLETE")
							if total_incomplete_hosts == 0:
								(ret, response_code, response_data) = hx_api_object.restDeleteJob('acqs/bulk', self.parent_task.stored_result['bulk_acquisition_id'])
								if ret:
									self.logger.info("Previous bulk acquisition job {} is complete, and has been removed.".format(self.parent_task.stored_result['bulk_acquisition_id']))
								else:
									self.logger.error("Failed to remove previous bulk acquisition job {}, error {}".format(self.parent_task.stored_result['bulk_acquisition_id'], response_data))
							else:
								self.logger.info("Previous bulk acquisition job {} is not complete, will not remove it.".format(self.parent_task.stored_result['bulk_acquisition_id']))
					(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(script, hostset_id = hostset_id, comment = comment, skip_base64 = False)
				if ret and '_id' in response_data['data']:
					result['bulk_acquisition_id'] = response_data['data']['_id']
					self.parent_task.name = "Bulk Acquisition ID: {}".format(response_data['data']['_id'])
					self.logger.info("Bulk acquisition ID {} submitted successfully.".format(response_data['data']['_id']))
					if download and bulk_download_eid:
						hxtool_global.hxtool_db.bulkDownloadUpdate(bulk_download_eid, bulk_acquisition_id = response_data['data']['_id'], hosts = {})
						result['bulk_download_eid'] = bulk_download_eid
				elif not ret:
					if self.can_retry(response_data):
						self.logger.warning("Bulk acquisition submission failed, will defer and retry up to {} times. Response code: {}, response data: {}".format(task_module.MAX_RETRY, response_code, response_data))
						self.retry_count +=1
						self.parent_task.defer()
						ret = True
					else:
						self.logger.error("Bulk acquisition submission failed and the retry count has been exceeded. Response code: {}, response data: {}".format(response_code, response_data))
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))
		else:
			self.logger.error("'script' is empty!")
		return(ret, result)