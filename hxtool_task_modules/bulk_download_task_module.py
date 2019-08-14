#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from .task_module import *
from hxtool_util import *

class bulk_download_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{ 
				'name' : 'bulk_download_eid',
				'type' : int,
				'required' : True,
				'user_supplied' : False,
				'description' : "The document ID of the bulk download job."
			}, 
			{
				'name' : 'agent_id',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host/agent ID of the bulk acquisition to download."
			},
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host name of the agent."
			}
		]
	
	@staticmethod
	def output_args():
		return [
			{
				'name' : 'bulk_acquisition_id',
				'type' : int,
				'required' : True,
				'description' : "The bulk acquisition ID assigned to the bulk acquisition job by the controller."
			},
			{ 
				'name' : 'bulk_download_path',
				'type' : str,
				'required' : True,
				'description' : "The fully qualified path to the bulk acquisition package."
			},
			{
				'name' : 'agent_id',
				'type' : str,
				'required' : True,
				'description' : "The host/agent ID of the bulk acquisition that was downloaded"
			},
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'description' : "The host name of the bulk acquisition that was downloaded."
			}
		]	
		
	def run(self, bulk_download_eid = None, agent_id = None, host_name = None):
		ret = False
		result = {}
		try:
			bulk_download_job = hxtool_global.hxtool_db.bulkDownloadGet(bulk_download_eid = bulk_download_eid)
			if bulk_download_job and bulk_download_job['stopped'] == False:
				hx_api_object = self.get_task_api_object()	
				if hx_api_object and hx_api_object.restIsSessionValid():
					(ret, response_code, response_data) = hx_api_object.restGetBulkHost(bulk_download_job['bulk_acquisition_id'], agent_id)
					if ret and isinstance(response_data, dict) and (response_data['data']['state'] == "COMPLETE" and response_data['data']['result']):
						self.logger.debug("Processing bulk download for host: {0}".format(host_name))
						download_directory = make_download_directory(hx_api_object.hx_host, bulk_download_job['bulk_acquisition_id'])
						full_path = os.path.join(download_directory, get_download_filename(host_name, agent_id))
						(ret, response_code, response_data) = hx_api_object.restDownloadFile(response_data['data']['result']['url'], full_path)
						if ret:
							hxtool_global.hxtool_db.bulkDownloadUpdateHost(bulk_download_eid, agent_id)
							self.logger.debug("Bulk download for host {} successfully downloaded to {}".format(host_name, full_path))
							result['bulk_acquisition_id'] = bulk_download_job['bulk_acquisition_id']
							result['bulk_download_path'] = full_path
							result['agent_id'] = agent_id
							result['host_name'] = host_name
					elif (ret and isinstance(response_data, dict) and (response_data['data']['state'] in {'FAILED', 'CANCELLED', 'ABORTED'} or 
													(response_code == 404 and response_data['details'][0]['code'] == 1005))) or not ret:
						self.logger.debug("Error! Controller returned code: {}, data: {}".format(response_code, response_data))
						self.parent_task.stop()
						hxtool_global.hxtool_db.bulkDownloadDeleteHost(bulk_download_eid, agent_id)
						ret = False
					elif ret:
						self.logger.debug("Deferring bulk download task for: {}".format(host_name))
						self.parent_task.defer()
				else:
					self.logger.warn("No task API session for profile: {}".format(self.parent_task.profile_id))
			else:
				self.logger.info("Bulk download is stopped.")
				self.parent_task.stop()
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
		finally:
			return(ret, result)
