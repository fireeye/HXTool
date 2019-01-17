#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import os
import json
import time
import tempfile
import gzip

import requests

import hxtool_global
from .task_module import *
from hx_audit import *

class helix_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def input_args():
		return [
			{
				'name' : 'host_name',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The host name belonging to the bulk acquisition package."
			},
			{
				'name' : 'agent_id',
				'type' : str,
				'required' : False,
				'user_supplied' : False,
				'description' : "The host/agent ID of the bulk acquisition to download."
			},
			{
				'name' : 'bulk_download_path',
				'type' : str,
				'required' : True,
				'user_supplied' : False,
				'description' : "The fully qualified path to the bulk acquisition package."
			},
			{
				'name' : 'bulk_acquisition_id',
				'type' : int,
				'required' : True,
				'description' : "The bulk acquisition ID assigned to the bulk acquisition job by the controller."
			},
			{
				'name' : 'delete_bulk_download',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Flag whether to delete the bulk acquisition package locally once complete. Defaults to False"
			},
			{
				'name' : 'apikey',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The API key for uploading"
			},
			{
				'name' : 'url',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The URL to which the upload is sent"
			}
				
		]
	
	@staticmethod
	def output_args():
		return []

	def _write_fh(self, gz_fh, bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id=None):
		gz = gzip.GzipFile(fileobj=gz_fh, mode='wb')
		for audit_object in self.yield_audit_results(bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = bulk_acquisition_id):
			gz.write(json.dumps(audit_object, sort_keys = False).encode('utf-8') + '\n'.encode('utf-8'))
		gz.close()
		gz_fh.seek(0)
	
	def run(self, host_name = None, agent_id = None, bulk_download_path = None, bulk_acquisition_id = None, batch_mode = False, delete_bulk_download = False, apikey = None, url = None):
		try:
			if not bulk_download_path:
				self.logger.error("bulk_download_path is empty!")
				return (False, None)
				
			resp = requests.post(url, headers={"x-api-key": apikey}, data={"host_name": host_name, "agent_id": agent_id, "bulk_acquisition_id": bulk_acquisition_id})
			if not resp:
				raise Exception("Unable to get upload link from URL {}: {}".format(url, resp))
			resp = resp.json()
			self.logger.debug("Uploading id {} from {} to {}".format(bulk_acquisition_id, bulk_download_path, resp["url"]))

			start = time.time()
			with tempfile.TemporaryFile(mode='r+b') as gz_fh:
				self._write_fh(gz_fh, bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = bulk_acquisition_id)
				resp = requests.post(resp["url"], data=resp["fields"], files={"file": (str(time.time()), gz_fh)})
				if not resp:
					raise Exception("Unable to upload: {} {}".format(resp, resp.text))
				self.logger.info("Uploaded id {} in {}".format(bulk_acquisition_id, (time.time() - start)))
				if delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))			
				return(True, None)
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
			return(False, None)