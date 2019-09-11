#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .task_module import *
import hxtool_global
from hxtool_util import *
from hxtool_scheduler import *

# TODO: fix this with a wildcard import
from .bulk_download_task_module import *
from .stacking_task_module import *
from .file_listing_task_module import *
from .file_acquisition_task_module import *
from .streaming_task_module import *
from .file_write_task_module import *
from .helix_task_module import *
from .x15_postgres_task_module import *

class bulk_download_monitor_task_module(task_module):


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
				'name' : 'task_profile',
				'type' : str,
				'required' : False,
				'user_supplied' : False,
				'description' : "The name of the task profile to use in post-processing this bulk acquisition."
			}
		]
	
	@staticmethod
	def output_args():
		return []
		
	def run(self, bulk_download_eid = None, task_profile = None):
		ret = False
		result = {}
		try:
			bulk_download_job = hxtool_global.hxtool_db.bulkDownloadGet(bulk_download_eid = bulk_download_eid)
			if bulk_download_job:
				if bulk_download_job['stopped'] == False:
					hx_api_object = self.get_task_api_object()
					if hx_api_object:
						(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(bulk_download_job['bulk_acquisition_id'])
						if ret:
							if response_data['data']['state'] != 'RUNNING':
								self.logger.error("The bulk acquisition job {} is not in a running state. Controller state: {}".format(bulk_download_job['bulk_acquisition_id'], response_data['data']['state']))
								hxtool_global.hxtool_db.bulkDownloadUpdate(bulk_download_job['bulk_acquisition_id'], stopped=True)
								self.parent_task.stop()
								return(ret, result)
						else:
							self.logger.error("Failed to get bulk acquisition job status for ID {}".format(bulk_download_job['bulk_acquisition_id']))
							self.parent_task.stop()
							return(ret, result)
						
						(ret, response_code, response_data) = hx_api_object.restListBulkHosts(bulk_download_job['bulk_acquisition_id'], filter_term = {'state' : 'COMPLETE'})
						if ret:
							for bulk_host in response_data['data']['entries']:
								# Don't create duplicate jobs for the same hosts
								if not bulk_download_job['hosts'].get(bulk_host['host']['_id'], None):
									# Set wait_for_parent to False, as the parent is already complete
									# if we've gotten to this point - and the task won't get a callback.
									hxtool_global.hxtool_db.bulkDownloadUpdateHost(bulk_download_eid, bulk_host['host']['_id'], hostname = bulk_host['host']['hostname'], downloaded = False)
									
									download_and_process_task = hxtool_scheduler_task(
																	self.parent_task.profile_id, 
																	'Bulk Acquisition Download: {}'.format(bulk_host['host']['_id']), 
																	parent_id = self.parent_task.parent_id,
																	wait_for_parent = False,
																	start_time = self.parent_task.start_time,
																	defer_interval = hxtool_global.hxtool_config['background_processor']['poll_interval']
																)
																
									download_and_process_task.add_step(
										bulk_download_task_module,
										kwargs = {
											'bulk_download_eid' : bulk_download_eid,
											'agent_id' : bulk_host['host']['_id'],
											'host_name' : bulk_host['host']['hostname']
										}
									)
									
									if task_profile == 'stacking':
										self.logger.debug("Using stacking task module.")
										# TODO: Maybe move this to the stacking module instead
										hxtool_global.hxtool_db.stackJobAddHost(self.parent_task.profile_id, bulk_download_eid, bulk_host['host']['hostname'])
										download_and_process_task.add_step(
											stacking_task_module, 
											kwargs = {
														'delete_bulk_download' : True
											}
										)
									elif task_profile == 'file_listing':
										self.logger.debug("Using file listing task module.")
										download_and_process_task.add_step(
											file_listing_task_module, 
											kwargs = {
														'delete_bulk_download' : False
											}
										)
									elif task_profile:
										_task_profile = hxtool_global.hxtool_db.taskProfileGet(task_profile)

										if _task_profile and 'params' in _task_profile:
											#TODO: once task profile page params are dynamic, remove static mappings
											for task_module_params in _task_profile['params']:						
												if task_module_params['module'] == 'ip':
													self.logger.debug("Using taskmodule 'ip' with parameters: protocol {}, ip {}, port {}".format(task_module_params['protocol'], task_module_params['targetip'], task_module_params['targetport']))
													download_and_process_task.add_step(streaming_task_module, kwargs = {
																						'stream_host' : task_module_params['targetip'],
																						'stream_port' : task_module_params['targetport'],
																						'stream_protocol' : task_module_params['protocol'],
																						'batch_mode' : (task_module_params['eventmode'] != 'per-event'),
																						'delete_bulk_download' : False
																					})
												elif task_module_params['module'] == 'file':
													self.logger.debug("Using taskmodule 'file' with parameters: filepath {}".format(task_module_params['filepath']))
													download_and_process_task.add_step(file_write_task_module, kwargs = {
																						'file_name' : task_module_params['filepath'],
																						'batch_mode' : (task_module_params['eventmode'] != 'per-event'),
																						'delete_bulk_download' : False
																					})
												elif task_module_params['module'] == 'helix':
													self.logger.debug("Using taskmodule 'helix' with parameters: helix_url {}, helix_apikey: {}".format(task_module_params['helix_url'], task_module_params['helix_apikey']))
													download_and_process_task.add_step(helix_task_module, kwargs = {
																						'url' : task_module_params['helix_url'],
																						'apikey' : task_module_params['helix_apikey'],
																						'batch_mode' : (task_module_params['eventmode'] != 'per-event'),
																						'delete_bulk_download' : False
																					})
												elif task_module_params['module'] == 'x15':
													self.logger.debug("Using taskmodule 'x15' with parameters: x15_host: {}, x15_port: {}, x15_database: {}, x15_table: {}, x15_user: {}, x15_password: {}".format(task_module_params['x15_host'], task_module_params['x15_port'], task_module_params['x15_database'], task_module_params['x15_table'], task_module_params['x15_user'], "********"))
													task_module_args = {
														'batch_mode' : False, # Hardcode per-event as X15 might not handle large lists well
														'delete_bulk_download' : False
													}
													task_module_args.update(task_module_params)
													del task_module_args['module']
													download_and_process_task.add_step(x15_postgres_task_module, kwargs = task_module_args)
									
									download_and_process_task.stored_result = self.parent_task.stored_result
									hxtool_global.hxtool_scheduler.add(download_and_process_task)
									
							
							self.parent_task.defer()
							ret = True
						else:
							self.logger.error("No task API session for profile: {}".format(self.parent_task.profile_id))
				else:
					self.logger.warning("Bulk download database entry {} is marked as stopped.".format(bulk_download_eid))
					self.parent_task.stop()
			else:
				self.logger.error("Bulk download database entry {} doesn't exist.".format(bulk_download_eid))
				self.parent_task.stop()
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
			ret = False
		finally:
			return(ret, result)
