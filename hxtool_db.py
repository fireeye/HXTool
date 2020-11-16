#!/usr/bin/env python
# -*- coding: utf-8 -*-

class hxtool_db:
	def __init__(self):
		pass

	@property
	def database_engine(self):
		raise NotImplementedError("You must override this in your database class.")