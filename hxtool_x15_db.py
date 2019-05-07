#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	import psycopg2
	import psycopg2.extras
except ImportError:
	print("HXTool with X15 integration requires the psycopg2 library please install it")
	exit(1)

import hxtool_global

class hxtool_x15:
	def __init__(self, x15conf = hxtool_global.hxtool_config['x15']):

		connect_string = "host={} dbname={} user={} port={} password={}".format(x15conf['host'], x15conf['db'], x15conf['user'], x15conf['port'], x15conf['password'])
		self.conn = psycopg2.connect(connect_string)
		self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

	def getAudits(self):
		self.cur.execute("SELECT bulk_acquisition_id, min(timestamps[1]['time']) as starttime, max(timestamps[1]['time']) as stoptime, count(*) as events FROM eventdata GROUP BY bulk_acquisition_id")
		return(self.cur.fetchall())

	def getAuditModules(self, bulk_list):
		self.cur.execute("SELECT generator, count(*) as events FROM eventdata WHERE bulk_acquisition_id IN %s GROUP BY generator", (tuple(bulk_list),))
		return(self.cur.fetchall())

	def getAuditData(self, generators, bulk_list):
		self.cur.execute("SELECT * FROM eventdata WHERE bulk_acquisition_id IN %(bulkids)s AND generator IN %(generators)s LIMIT 1", {"bulkids": tuple(bulk_list), "generators": tuple(generators)})
		return(self.cur.fetchall())				
