#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *
from hx_lib import *

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
				'description' : "Specifies whether we should create a bulk download job after this bulk acquisition is submitted."
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
			if hx_api_object and hx_api_object.restIsSessionValid():
				bulk_acquisition_id = None
				# TODO: replace macro values in bulk acquisition script
				(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(script, hostset_id = hostset_id, comment = comment, skip_base64 = skip_base64)
				if ret and '_id' in response_data['data']:
					result['bulk_acquisition_id'] = response_data['data']['_id']
					self.parent_task.name = "Bulk Acquisition ID: {}".format(response_data['data']['_id'])
					self.logger.info("Bulk acquisition ID {} submitted successfully.".format(response_data['data']['_id']))
					if download and bulk_download_eid:
						hxtool_global.hxtool_db.bulkDownloadUpdate(bulk_download_eid, bulk_acquisition_id = response_data['data']['_id'])
						result['bulk_download_eid'] = bulk_download_eid
				else:
					self.logger.error("Bulk acquisition submission failed. Response code: {}, response data: {}".format(response_code, response_data))
			else:
				self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))
		else:
			self.logger.error("'script' is empty!")
		return(ret, result)