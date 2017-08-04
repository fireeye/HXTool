#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading			
import time
import zipfile
import json	
import xml.etree.ElementTree as ET
import os

try:
	import Queue as queue
except ImportError:
	import queue

try:
	from StringIO import StringIO
except ImportError:
	# Running on Python 3.x
	from io import StringIO

from hxtool_db import *
from hx_lib import *
from hxtool_data_models import *

def parseXmlServiceMD5Data(sourcedata):

	tree = ET.ElementTree(ET.fromstring(sourcedata))
	root = tree.getroot()

	acqdata = []

	for child in root:
		store = {}
		for data in child:
			store[data.tag] = data.text
		acqdata.append(store)
	
	return(acqdata)

"""
Multi-threaded bulk download

thread_count: Assume most systems are quad core, so 4 threads should be optimal - 1 thread per core
"""					
class hxtool_background_processor:
	def __init__(self, hxtool_config, hxtool_db, profile_id, thread_count = 4, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._ht_db = hxtool_db
		# TODO: maybe replace with hx_hostname, hx_port variables in __init__
		profile = self._ht_db.profileGet(profile_id)
		self._hx_api_object = HXAPI(profile['hx_host'], profile['hx_port'])
		self.profile_id = profile_id
		self.thread_count = thread_count
		self._task_queue = queue.Queue()
		self._task_thread_list = []
		self._stack_data_model_instance = None
		self._stop_event = threading.Event()
		self._poll_thread = threading.Thread(target = self.bulk_download_processor, name = "hxtool_background_processor", args = (hxtool_config['background_processor']['poll_interval'], ))
		# TODO: should be configurable
		self._download_directory_base = "bulkdownload"
		
	def __exit__(self, exc_type, exc_value, traceback):
		self.stop()
		
	def start(self, hx_api_username, hx_api_password):
		(ret, response_code, response_data) = self._hx_api_object.restLogin(hx_api_username, hx_api_password)
		if ret:
			self._poll_thread.start()
			for i in range(1, self.thread_count):
				task_thread = threading.Thread(target = self.await_task)
				self._task_thread_list.append(task_thread)
				task_thread.start()
		else:
			self.logger.error("Failed to login to the HX controller! Error: {0}".format(response_data))
			self.stop()
		
	def stop(self):
		self._stop_event.set()
		if self._poll_thread.is_alive():
			self._poll_thread.join()
		for task_thread in [_ for _ in self._task_thread_list if _.is_alive()]:
			task_thread.join()
		if self._hx_api_object.restIsSessionValid():
			(ret, response_code, response_data) = self._hx_api_object.restLogout()

	def bulk_download_processor(self, poll_interval):
		while not self._stop_event.is_set():
			bulk_download_jobs = self._ht_db.bulkDownloadList(self.profile_id)
			for job in [_ for _ in bulk_download_jobs if not _['stopped']]:
				download_directory = self.make_download_directory(job['bulk_download_id'])
				for host_id, host in [(_, job['hosts'][_]) for _ in job['hosts'] if not job['hosts'][_]['downloaded']]:
					(ret, response_code, response_data) = self._hx_api_object.restGetBulkHost(job['bulk_download_id'], host_id)
					if ret:
						if response_data['data']['state'] == "COMPLETE" and response_data['data']['result']:
							full_path = os.path.join(download_directory, '{0}_{1}.zip'.format(host['hostname'], host_id))
							self._task_queue.put((self.download_task, (job['bulk_download_id'], host_id, host['hostname'], job['stack_job'], response_data['data']['result']['url'], full_path)))
			time.sleep(poll_interval)
			
	def await_task(self):
		while not self._stop_event.is_set():
			task = self._task_queue.get()
			task[0](*task[1])
			self._task_queue.task_done()
			
	def download_task(self, bulk_download_id, host_id, hostname, is_stack_job, download_url, destination_path):
		(ret, response_code, response_data) = self._hx_api_object.restDownloadFile(download_url, destination_path)
		if ret:
			self._ht_db.bulkDownloadUpdateHost(self.profile_id, bulk_download_id, host_id)
			if is_stack_job:
				with zipfile.ZipFile(destination_path) as f:
					acquisition_manifest = json.loads(f.read('manifest.json'))
					if acquisition_manifest['audits'][0]['results'][0]['type'] == "application/xml":
						results_file = acquisition_manifest['audits'][0]['results'][0]['payload']	
						results = f.read(results_file)
						stack_job = self._ht_db.stackJobGet(self.profile_id, bulk_download_id)
						data_model = hxtool_data_models(stack_job['stack_type'])
						results_dict = data_model.xml_to_dict(hostname, results)
						self._ht_db.stackJobAddResult(self.profile_id, bulk_download_id, results_dict)
		
			
	def make_download_directory(self, bulk_download_id):
		download_directory = os.path.join(self._download_directory_base, self._hx_api_object.hx_host, str(bulk_download_id))
		if not os.path.exists(download_directory):
			os.makedirs(download_directory)
		return download_directory