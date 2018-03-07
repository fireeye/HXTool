#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from task_module import *
from hxtool_util import *
from hx_lib import *
from hxtool_scheduler import *
from download_task_module import *


class bulk_download_scheduler_task_module(task_module):
	def __init__(self, profile_id):
		super(bulk_download_scheduler_task_module, self).__init__(profile_id)

	def run(self):
		hx_api_object = hxtool_global.task_hx_api_sessions[self.profile_id]	
		if hx_api_object and hx_api_object.restIsSessionValid():
			bulk_download_jobs = hxtool_global.hxtool_db.bulkDownloadList(self.profile_id)
			for job in [_ for _ in bulk_download_jobs if not _['stopped'] or ('complete' in _ and _['complete'])]:
				if len(job['hosts']) == len([_ for _ in job['hosts'] if _['downloaded']]):
					hxtool_global.hxtool_db.bulkDownloadComplete(self.profile_id, job['bulk_download_id'])
				else:	
					self.logger.debug("Processing bulk download job id: {0}, post download handler: {1}.".format(job['bulk_download_id'], job['post_download_handler']))
					download_directory = make_download_directory(hx_api_object.hx_host, job['bulk_download_id'])
					for host_id, host in [(_, job['hosts'][_]) for _ in job['hosts'] if not job['hosts'][_]['downloaded']]:
						(ret, response_code, response_data) = hx_api_object.restGetBulkHost(job['bulk_download_id'], host_id)
						if ret:
							if response_data['data']['state'] == "COMPLETE" and response_data['data']['result']:
								self.logger.debug("Processing bulk download host: {0}".format(host['hostname']))
								full_path = os.path.join(download_directory, get_download_filename(host['hostname'], host_id))
								download_task = hxtool_scheduler_task(self.profile_id, "Acquisition download for: {}".format(host['hostname']))
								download_task.add_step(download_task_module(self.profile_id).run, (response_data['data']['result']['url'], full_path, job['bulk_download_id'], host_id))
								hxtool_global.hxtool_scheduler.add(download_task)
				
	