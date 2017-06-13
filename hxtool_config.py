#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging

class hxtool_config:
	def __init__(self, config_file, logger = logging.getLogger(__name__)):
		self.logger = logger
		
		self.logger.info('Reading configuration file %s', config_file)
		with open(config_file, 'r') as config_file_handle:
			self._config = json.load(config_file_handle)
			self.logger.info('Checking configuration file %s', config_file)
			if not ['network', 'backgroundProcessor', 'ssl'] <= self._config.keys():
				raise ValueError('Configuration file is missing key elements!')
			else:
				self.logger.info('Configuration file %s is OK.', config_file)

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
			