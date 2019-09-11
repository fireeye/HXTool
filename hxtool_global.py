#!/usr/bin/env python
# -*- coding: utf-8 -*-

# The sole purpose of this module is to store global variables and functions

def initialize():
	global task_hx_api_sessions
	task_hx_api_sessions = {}
	
	global hxtool_db
	global hxtool_config
	global hxtool_scheduler
	global hxtool_x15_object