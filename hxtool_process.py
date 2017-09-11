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
from hx_audit import *

# TODO: should be configurable
_download_directory_base = "bulkdownload"

def get_download_directory(hx_host, download_id, job_type=None):
	if job_type:
		return os.path.join(_download_directory_base, hx_host, job_type, str(download_id))
	else:
		return os.path.join(_download_directory_base, hx_host, str(download_id))

def get_download_filename(hostname, _id):
	return '{0}_{1}.zip'.format(hostname, _id)

def get_download_full_path(hx_host, download_id, job_type, hostname, _id):
	return os.path.join(get_download_directory(hx_host, download_id, job_type), get_download_filename(hostname, _id))

def make_download_directory(host, download_id, job_type=None):
	download_directory = get_download_directory(host, download_id, job_type)
	if not os.path.exists(download_directory):
		os.makedirs(download_directory)
	return download_directory
		
"""
Multi-threaded bulk download

thread_count: Assume most systems are quad core, so 4 threads should be optimal - 1 thread per core
"""					
class hxtool_background_processor:
	def __init__(self, hxtool_config, hxtool_db, profile_id, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._ht_db = hxtool_db
		# TODO: maybe replace with hx_hostname, hx_port variables in __init__
		profile = self._ht_db.profileGet(profile_id)
		self._hx_api_object = HXAPI(profile['hx_host'], profile['hx_port'])
		self._hx_api_lock = threading.Lock()
		self.profile_id = profile_id
		self.thread_count = hxtool_config['background_processor']['poll_threads']
		if not self.thread_count:
			self.thread_count = 4
		self._task_queue = queue.Queue()
		self._task_thread_list = []
		self._stop_event = threading.Event()
		self._poll_thread = threading.Thread(target = self.bulk_download_processor, name = "hxtool_background_processor", args = (hxtool_config['background_processor']['poll_interval'], ))
		
	def __exit__(self, exc_type, exc_value, traceback):
		self.stop()
		
	def start(self, hx_api_username, hx_api_password):
		self._hx_api_username = hx_api_username
		self._hx_api_password = hx_api_password
		(ret, response_code, response_data) = self.hx_api_object(renew_expired_token = False).restLogin(hx_api_username, hx_api_password)
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
		if self.hx_api_object(renew_expired_token = False).restIsSessionValid():
			(ret, response_code, response_data) = self.hx_api_object(renew_expired_token = False).restLogout()

	def hx_api_object(self, renew_expired_token = True):
		if renew_expired_token and not self._hx_api_object.restIsSessionValid():
			with self._hx_api_lock:
				(ret, response_code, response_data) = self._hx_api_object.restLogin(self._hx_api_username, self._hx_api_password)
				if not ret:
					raise ValueError("HX controller returned code: %s, message: %s.", response_code, response_data)
		return self._hx_api_object
		
	def bulk_download_processor(self, poll_interval):
		while not self._stop_event.is_set():
			bulk_download_jobs = self._ht_db.bulkDownloadList(self.profile_id)
			for job in [_ for _ in bulk_download_jobs if not _['stopped']]:
				download_directory = make_download_directory(self.hx_api_object().hx_host, job['bulk_download_id'])
				for host_id, host in [(_, job['hosts'][_]) for _ in job['hosts'] if not job['hosts'][_]['downloaded']]:
					(ret, response_code, response_data) = self.hx_api_object().restGetBulkHost(job['bulk_download_id'], host_id)
					if ret:
						if response_data['data']['state'] == "COMPLETE" and response_data['data']['result']:
							full_path = os.path.join(download_directory, get_download_filename(host['hostname'], host_id))
							self._task_queue.put((self.download_task, (job['bulk_download_id'], host_id, host['hostname'], job['post_download_handler'], response_data['data']['result']['url'], full_path)))
			# Process Multi-File Acquisitions
			for job in [_ for _ in self._ht_db.multiFileList(self.profile_id) if not _['stopped']]:
				download_directory = make_download_directory(self.hx_api_object().hx_host, job.eid, job_type='multi_file')
				for file_acq in [_ for _ in job['files'] if not _['downloaded']]:
					(ret, response_code, response_data) = self._hx_api_object.restFileAcquisitionById(file_acq['acquisition_id'])
					if ret:
						if response_data['data']['state'] == "COMPLETE" and response_data['data']['url']:
							full_path = os.path.join(download_directory, get_download_filename(file_acq['hostname'], file_acq['acquisition_id']))
							self._task_queue.put((self.download_file, (job.eid, file_acq, response_data['data']['url']+'.zip', full_path)))
			time.sleep(poll_interval)
			
	def await_task(self):
		while not self._stop_event.is_set():
			task = self._task_queue.get()
			task[0](*task[1])
			self._task_queue.task_done()
			
	def download_file(self, multi_file_id, file_acq, download_url, destination_path):
		try:
			(ret, response_code, response_data) = self._hx_api_object.restDownloadFile(download_url, destination_path)
			if ret:
				self._ht_db.multiFileUpdateFile(self.profile_id, multi_file_id, file_acq['acquisition_id'])
				self.logger.info("File Acquisition download complete. Acquisition ID: {0}, Batch: {1}".format(file_acq['acquisition_id'], multi_file_id))
		except:
			# TODO: re-raise for now, need to handle specific errors
			raise
				
	def download_task(self, bulk_download_id, host_id, hostname, post_download_handler, download_url, destination_path):
		try:
			(ret, response_code, response_data) = self.hx_api_object().restDownloadFile(download_url, destination_path)
			if ret:
				# TODO: commenting out for now as a stopped bulk download job
				# will still give the option to download the individual host
				# acquisitions, which will result in a 404
				# self.hx_api_object().restDeleteFile(download_url)
				if post_download_handler:
					handler = self.post_download_handlers.get(post_download_handler)
					if handler is not None:
						self.logger.debug("Executing Post-Process Handler. bulk job: {0} host: {1}".format(bulk_download_id, hostname))
						if handler(self, bulk_download_id, destination_path, hostname):
							# TODO: check to see if the user chose to keep the bulk acquisition package
							# even after post processing
							os.remove(os.path.realpath(destination_path))
				self._ht_db.bulkDownloadUpdateHost(self.profile_id, bulk_download_id, host_id)
				self.logger.debug("Bulk Download complete. bulk job: {0} host: {1}".format(bulk_download_id, hostname))
		except:
			# TODO: re-raise for now, need to handle specific errors
			raise
				
	def file_listing_handler(self, bulk_download_id, acquisition_package_path, hostname):
		audit_pkg = AuditPackage(acquisition_package_path)
		audit_data = audit_pkg.get_audit(generator='w32rawfiles')
		if audit_data:
			files = get_audit_records(audit_data, 'w32rawfiles', 'FileItem', hostname=hostname)
			if files:
				self._ht_db.fileListingAddResult(self.profile_id, bulk_download_id, files)
				self.logger.debug("File Listing added to the database. bulk job: {0} host: {1}".format(bulk_download_id, hostname))
		#TODO: What if no results?
		return True
	
	def stacking_handler(self, bulk_download_id, acquisition_package_path, hostname):
		ret = False
		try:
			stack_job = self._ht_db.stackJobGet(self.profile_id, bulk_download_id)
			stack_model = hxtool_data_models(stack_job['stack_type'])._stack_type
			audit_pkg = AuditPackage(acquisition_package_path)
			audit_data = audit_pkg.get_audit(generator=stack_model['audit_module'])
			if audit_data:
				records = get_audit_records(audit_data, stack_model['audit_module'], stack_model['item_name'], fields=stack_model['fields'], post_process=stack_model['post_process'], hostname=hostname)
				if records:
					self._ht_db.stackJobAddResult(self.profile_id, bulk_download_id, records)
					self.logger.debug("Stacking Records added to the database for bulk job {0} host {1}".format(bulk_download_id, hostname))
					return True
			else:
				self.logger.warning("WARNING: No audit data for hostname %s of stack_job %s", hostname, str(bulk_download_id))
		except:
			# TODO: re-raise for now, need to handle specific errors
			raise
		#TODO: What if no results?
		return False
	
	post_download_handlers = {
		"stacking" : stacking_handler,
		"file_listing" : file_listing_handler
	}	
