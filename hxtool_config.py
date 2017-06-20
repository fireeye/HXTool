#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
from os import path

#TODO: Add config documentation

class hxtool_config:
	DEFAULT_CONFIG = {
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


	def __init__(self, config_file, logger = logging.getLogger(__name__)):
		self.logger = logger
		
		self.logger.info('Reading configuration file %s', config_file)
		if path.isfile(config_file):
			with open(config_file, 'r') as config_file_handle:
				self._config = json.load(config_file_handle)
				self.logger.info('Checking configuration file %s', config_file)
				if not {'network', 'ssl', 'background_processor'} <= set(self._config.keys()):
					raise ValueError('Configuration file is missing key elements!')
				else:
					self.logger.info('Configuration file %s is OK.', config_file)
		else:
			self.logger.warning('Unable to open config file: %s, loading default config.', config_file)
			self._config = DEFAULT_CONFIG

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
			