#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
try:
	from io import StringIO
except ModuleNotFoundError:
	from cStringIO import StringIO

import hxtool_global
from .task_module import *
from hx_audit import *
from hxtool_util import *

class x15_postgres_task_module(task_module):
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
				'name' : 'batch_mode',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Flag whether to batch each audit as single JSON object versus sending each record as a separate object. Defaults to False"
			},
			{
				'name' : 'delete_bulk_download',
				'type' : bool,
				'required' : False,
				'user_supplied' : True,
				'description' : "Flag whether to delete the bulk acquisition package locally once complete. Defaults to False"
			},
			{
				'name' : 'x15_host',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The IP address or fully qualified domain name of the X15 server."
			},
			{
				'name' : 'x15_port',
				'type' : int,
				'required' : True,
				'user_supplied' : True,
				'description' : "The Postgres port on the X15 server."
			},
			{
				'name' : 'x15_user',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The username with which to authenticate to the X15 server."
			},
			{
				'name' : 'x15_password',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The password with which to authenticate to the X15 server."
			},
			{
				'name' : 'x15_database',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The database to utilize on the X15 server."
			},
			{
				'name' : 'x15_table',
				'type' : str,
				'required' : True,
				'user_supplied' : True,
				'description' : "The table in the database to utilize."
			}
		]
	
	@staticmethod
	def output_args():
		return []
	
	def run(self, host_name = None, agent_id = None, bulk_download_path = None, bulk_acquisition_id = None, batch_mode = False, delete_bulk_download = False, x15_host = None, x15_port = None, x15_user = None, x15_password = None, x15_database = None, x15_table = None):
		
		ret = False
		result = {}
		try:
			import psycopg2
		
			if bulk_download_path:
				x15_connection_string = "host={} port={} dbname={} user={}  password={}".format(x15_host, x15_port, x15_database, x15_user, x15_password)
				x15_connection = psycopg2.connect(x15_connection_string)
				x15_cursor = x15_connection.cursor()
				x15_query = "COPY {} from stdin".format(x15_table)
				
				for audit_object in self.yield_audit_results(bulk_download_path, batch_mode, host_name, agent_id, bulk_acquisition_id = bulk_acquisition_id):
					buffer = StringIO()
					json.dump(audit_object, buffer)
					x15_cursor.copy_expert(x15_query, buffer)
				
				x15_connection.commit()
				x15_connection.close()
				
				ret = True								
				if ret and delete_bulk_download:
					os.remove(os.path.realpath(bulk_download_path))
				
			else:
				self.logger.error("bulk_download_path is empty!")
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
		finally:	
			return(ret, result)