#!/usr/bin/env python
# -*- coding: utf-8 -*-

from gunicorn.app.base import Application

class GunicornContainerApplication(Application):
	def __init__(self, app, options = {}):
		self.application = app
		self.options = options
		super(GunicornContainerApplication, self).__init__()

	def load_config(self):
		config = dict([(key, value) for key, value in self.options.items() 
						if key in self.cfg.settings and value is not None])
		for key, value in config.items():
			self.cfg.set(key.lower(), value)
				
	def load(self):
		return self.application
