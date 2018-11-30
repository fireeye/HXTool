#!/usr/bin/env python
# -*- coding: utf-8 -*-

# The sole purpose of this module is to store global variables

hxtool_schema_version = 40


def initialize():
	global task_hx_api_sessions
	task_hx_api_sessions = {}