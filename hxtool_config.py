#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

class hxtool_config:
	def __init__(self, config_file, app_logger):
		app_logger.info('Reading configuration file conf.json')
		with open(config_file, 'r') as config_file_handle:
			self._config = json.load(config_file_handle)
			app_logger.info('Checking configuration file {0}'.format(config_file))
			if not ['network', 'backgroundProcessor', 'ssl'] <= self._config.keys():
				raise ValueError('Configuration file is missing key elements!')
			else:
				app_logger.info('Configuration file {0} is OK.'.format(config_file))

	def get_config(self):
		return self._config	