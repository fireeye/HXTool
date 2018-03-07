#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from hx_lib import *	
	
class task_module(object):
	def __init__(self, profile_id):
		self.profile_id = profile_id
		self.logger = hxtool_global.hxtool_scheduler.logger
	
	def run(self):
		raise NotImplementedError("You must override run() in your task modules.")