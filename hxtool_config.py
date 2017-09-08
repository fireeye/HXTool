#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
from os import path
import sys, logging, logging.handlers, socket

#TODO: Add config documentation

class hxtool_config:
	"""
	Default hard coded config
	"""
	DEFAULT_CONFIG = {
		'log_handlers' : {
			'rotating_file_handler' : {
				'file' : 'log/hxtool.log',
				'max_bytes' : 50000,
				'backup_count' : 5,
				'level' : 'info',
				'format' : '[%(asctime)s] {%(module)s} {%(threadName)s} %(levelname)s - %(message)s'
			}
		},
		'network' : {
			'ssl' : 'enabled',
			'port' : 8080,
			'listen_address' : '0.0.0.0'
		},
		'ssl' : {
			'cert' : 'hxtool.crt',
			'key' : 'hxtool.key'
		},
		'background_processor' : {
			'downloads_per_poll' : 500,
			'poll_interval' : 5,
			'poll_threads'	: 4,
			'stack_jobs_per_poll' : 500
		},
		'headers' : {
		},
		'cookies' : {
		}
	}

	LOG_LEVELS = {
			'debug' : logging.DEBUG,
			'info' : logging.INFO,
			'warning' : logging.WARNING,
			'error' : logging.ERROR,
			'critical' : logging.CRITICAL
		}
	
	def __init__(self, config_file, logger = logging.getLogger(__name__)):
		self.logger = logger
		
		self.logger.info('Reading configuration file %s', config_file)
		if path.isfile(config_file):
			with open(config_file, 'r') as config_file_handle:
				self._config = json.load(config_file_handle)
				self.logger.info('Checking configuration file %s', config_file)
				if not {'log_handlers', 'network', 'ssl', 'background_processor'} <= set(self._config.keys()):
					raise ValueError('Configuration file is missing key elements!')
				else:
					self.logger.info('Configuration file %s is OK.', config_file)
				
				if 'proxies' in self._config['network']:
					if not {'http', 'https'} <= set(self._config['network']['proxies'].keys()):
						self.logger.warning("Ignoring invalid proxy configuration! Please see http://docs.python-requests.org/en/master/user/advanced/")
						del self._config['network']['proxies']
		else:
			self.logger.warning('Unable to open config file: %s, loading default config.', config_file)
			self._config = self.DEFAULT_CONFIG

	def __getitem__(self, key, default = None):
		v = self._config.get(key)
		if not v:
			v = default
		return v
		
	def get_config(self):
		return self._config
			
	def log_handlers(self):
		for handler_name in self._config['log_handlers']:
			if handler_name == 'rotating_file_handler':
				handler_config = self._config['log_handlers'][handler_name]
				if 'file' in handler_config:
					h = logging.handlers.RotatingFileHandler(handler_config['file'])
					
					if 'max_bytes' in handler_config:
						h.maxBytes = handler_config['max_bytes']
					if 'backup_count' in handler_config:
						h.backupCount = handler_config['backup_count']
					
					self._set_level_and_format(handler_config, h)
					yield(h)
					
			elif handler_name == 'syslog_handler':
				handler_config = self._config['log_handlers'][handler_name]

				address_tuple = ('127.0.0.1', logging.handlers.SYSLOG_UDP_PORT)
				if 'address' in handler_config:
					address_tuple[0] = handler_config['address']
				if 'port' in handler_config and 0 < handler_config['port'] < 65535:
					address_tuple[1] = handler_config['port']

				facility = logging.handlers.SysLogHandler.LOG_USER
				if 'facility' in handler_config:
					facility = logging.handlers.SysLogHandler.facility_names.get(handler_config['facility'])
				
				socket_type = socket.SOCK_DGRAM
				if 'protocol' in handler_config and handler_config['protocol'].lower() == 'tcp':
					socket_type = socket.SOCK_STREAM
					
				h = logging.handlers.SysLogHandler(address = address_tuple, facility = facility, socktype = socket_type)
				
				self._set_level_and_format(handler_config, h)
				yield(h)
	
	def _set_level_and_format(self, handler_config, handler):
		level = logging.WARNING
		if 'level' in handler_config:
			level = self.LOG_LEVELS.get(handler_config['level'].lower())
		
		handler.setLevel(level)
		
		if 'format' in handler_config:
			handler.setFormatter(logging.Formatter(handler_config['format']))
