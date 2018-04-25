#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import os
import json

import hxtool_global
from .task_module import *
from hx_audit import *

class streaming_task_module(task_module):
	def __init__(self, parent_task):
		super(type(self), self).__init__(parent_task)
	
	@staticmethod
	def run_args():
		return [
			'host_name',
			'bulk_download_path',
			'delete_bulk_download',
			'stream_protocol',
			'stream_host',
			'stream_port'
		]
	
	def run(self, host_name = None, bulk_download_path = None, delete_bulk_download = False, stream_protocol = 'tcp', stream_host = None, stream_port = None):
		try:
			ret = False
			if bulk_download_path:
				audit_objects = []
				with AuditPackage(bulk_download_path) as audit_pkg:
					for audit in audit_pkg.audits:
						for result in audit['results']:
							if result['type'] == 'application/xml':							
								audit_dict = audit_pkg.audit_to_dict(result['payload'])
								if audit_dict:
									audit_objects.append({
										'hostname' : host_name,
										'generator' : audit['generator'],
										'generatorVersion' : audit['generatorVersion'],
										'timestamps' : audit['timestamps'],
										'results' : audit_dict
									})
								
				if len(audit_objects) > 0:
					socket_type = socket.SOCK_STREAM
					if stream_protocol == 'udp':
						socket_type = socket.SOCK_DGRAM
					address_family, socktype, proto, canonname, sockaddr = socket.getaddrinfo(stream_host, stream_port, socket.AF_UNSPEC, socket_type)
					stream_socket = socket.socket(address_family, socktype, proto)
					socket.connect(sockaddr)
					socket.sendall(json.dumps(audit_objects, sort_keys = False, indent = 4))
					socket.close()
								
					ret = True
				else:
					self.logger.warn("Streaming: No audit data for {} from bulk acquisition {}".format(host_name, bulk_acquisition_id))
												
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
				
			else:
				self.logger.error("bulk_download_path is empty!")
				
			return(ret, None)
		except Exception as e:
			self.logger.error(e)
			return(False, None)