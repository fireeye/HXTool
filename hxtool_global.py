#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

# The sole purpose of this module is to store global variables and functions

hxtool_schema_version = 40
root_logger_name = "hxtool"

def initialize():
	global task_hx_api_sessions
	task_hx_api_sessions = {}
	
	global app_instance_path
	app_instance_path = None
	
def get_submodule_logger_name(name):
	return "{}.{}".format(root_logger_name, name)	
	
def get_logger(submodule_name = None):
	name = root_logger_name
	if submodule_name:
		name = get_submodule_logger_name(submodule_name)
	return logging.getLogger(name)
