#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
from os import path
import sys, logging, logging.handlers, socket

#TODO: Add config documentation

class hxtool_config:
	DEFAULT_CONFIG = {
		'log_handlers' : {
			'stream_handler' : {
				'level' : 'info',
				'format' : '[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s'
			},
			'rotating_file_handler' : {
				'file' : 'log/hxtool.log',
				'max_bytes' : 50000,
				'backup_count' : 5,
				'level' : 'info',
				'format' : '[%(asctime)s] {%(threadName)s} %(levelname)s - %(message)s'
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
		else:
			self.logger.warning('Unable to open config file: %s, loading default config.', config_file)
			self._config = self.DEFAULT_CONFIG

	def __getitem__(self, key):
		return self._config[key]
				
	def get_config(self):
		return self._config
	
	def get_or_none(self, key, empty_is_none = True):
		if key in self._config:
			c = self._config[key]
			if empty_is_none and len(c) == 0:
				return None
			else:
				return c
		else:
			return None
			
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
					
			elif handler_name == 'stream_handler':
				handler_config = self._config['log_handlers'][handler_name]
				h = logging.StreamHandler(sys.stdout)
				self._set_level_and_format(handler_config, h)
				yield(h)
				
			elif handler_name == 'syslog_handler':
				handler_config = self._config['log_handlers'][handler_name]

				address_tuple = ('127.0.0.1', logging.SYSLOG_UDP_PORT)
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
