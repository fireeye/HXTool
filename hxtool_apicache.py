#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_logging
import hxtool_global
import time
from hx_lib import *
from hxtool_scheduler import *
from hxtool_db import *

class hxtool_api_cache:
	def __init__(self, hx_api_object, profile_id, intervals, objectTypes):
		self.logger = hxtool_logging.getLogger(__name__)
		self.hx_api_object = hx_api_object
		self.profile_id = profile_id

		# TEMP: drop cache
		hxtool_global.hxtool_db.cacheDrop(self.profile_id)

		for objectType in objectTypes:
			if objectType in intervals.keys():
				try:
					setattr(self, objectType + "_fetcher_interval", intervals[objectType]["fetcher_interval"])
					setattr(self, objectType + "_objects_per_poll", intervals[objectType]["objects_per_poll"])
					setattr(self, objectType + "_refresh_interval", intervals[objectType]["refresh_interval"])
				except:
					self.logger.error("Missing interval settings for {}, check configuration to enable cache".format(objectType))
					exit(2)

				my_fetcher_task = hxtool_scheduler_task("System", "Cache fetcher for " + objectType + " profile: " + str(self.profile_id), immutable=True)
				my_fetcher_task.set_schedule(seconds=intervals[objectType]["fetcher_interval"])
				my_fetcher_task.add_step(self, "apicache_fetcher", kwargs={"objectType" : objectType } )
				hxtool_global.hxtool_scheduler.add(my_fetcher_task)
				self.logger.info("Apicache {} fetcher started for profile: {}.".format(objectType, self.profile_id))

		# Number of objects that can be fetched per second
		#self.fetcher_capability = self.objects_per_poll // self.fetcher_interval

		# Number of updater polls that can be made during the refresh_interval
		#self.updater_capability_attempts = self.refresh_interval // self.updater_interval

		# Number of records that can be updated within the refresh_interval
		#self.updater_capability = self.updater_capability_attempts * self.max_refresh_per_run

		# Tell hxtool_global about our stats
		hxtool_global.apicache = {}
		#hxtool_global.apicache['fetcher_capability'] = self.fetcher_capability
		#hxtool_global.apicache['updater_capability'] = self.updater_capability
		#hxtool_global.apicache['updater_capability_attempts'] = self.updater_capability_attempts

	def apicache_processor(self, currOffset, objectType, records, myCache, refresh_interval):

		for record in records:
			
			currOffset += 1

			if record['_id'] in myCache.keys():
				t = datetime.datetime.now() - datetime.datetime.strptime(myCache[record['_id']], "%Y-%m-%d %H:%M:%S")
				if t.seconds > refresh_interval:
					hxtool_global.hxtool_db.cacheUpdate(self.profile_id, objectType, record['_id'], record)
					self.logger.info("{}: {} record updated: {}".format(self.profile_id, objectType, record['_id']))

					# Special case, also get sysinfo for hosts
					if objectType == "host":
						(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(record['_id'])
						if ret:
							hxtool_global.hxtool_db.cacheUpdate(self.profile_id, "sysinfo", record['_id'], response_data['data'])
							self.logger.info("{}: Host sysinfo record updated: {}".format(self.profile_id, record['_id']))
			else:
				hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, record)
				self.logger.info("{}: New {} record added: {}".format(self.profile_id, objectType, record['_id']))

				# Special case, also get sysinfo for hosts
				if objectType == "host":
					(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(record['_id'])
					if ret:
						hxtool_global.hxtool_db.cacheAddById(self.profile_id, "sysinfo", record['_id'], response_data['data'])
						self.logger.info("{}: New sysinfo record added: {}".format(self.profile_id, record['_id']))

		return currOffset

	def apicache_fetcher(self, objectType):

		#Temp workaround
		time.sleep(2)

		# Get a list of current cache entries for this object type
		res = hxtool_global.hxtool_db.cacheList(self.profile_id, objectType)

		# Format the local cache results into a dict
		myCache = {}
		for cacheEntry in res:
			myCache[cacheEntry['contentId']] = cacheEntry['update_timestamp']
		
		# We always start the query from the top (always check everything)
		myoffset = 0

		if objectType == "host":
			while True:
				(ret, response_code, response_data) = self.hx_api_object.restListHosts(offset=myoffset, sort_term="_id+ascending", limit=self.host_objects_per_poll)
				if ret:
					# Leave loop if no new records are returned
					if len(response_data['data']['entries']) == 0:
						break
					myoffset = self.apicache_processor(myoffset, objectType, response_data['data']['entries'], myCache, self.host_refresh_interval)

		elif objectType == "alert":
			while True:
				(ret, response_code, response_data) = self.hx_api_object.restGetAlerts(offset=myoffset, sort_term="_id+ascending", limit=self.alert_objects_per_poll)
				if ret:
					if len(response_data['data']['entries']) == 0:
						break
					myoffset = self.apicache_processor(myoffset, objectType, response_data['data']['entries'], myCache, self.alert_refresh_interval)

		elif objectType == "triage":
			while True:
				(ret, response_code, response_data) = self.hx_api_object.restListTriages(offset=myoffset, sort_term="_id+ascending", limit=self.triage_objects_per_poll)
				if ret:
					if len(response_data['data']['entries']) == 0:
						break
					myoffset = self.apicache_processor(myoffset, objectType, response_data['data']['entries'], myCache, self.triage_refresh_interval)

		elif objectType == "file":
			while True:
				(ret, response_code, response_data) = self.hx_api_object.restListFileaq(offset=myoffset, sort_term="_id+ascending", limit=self.file_objects_per_poll)
				if ret:
					if len(response_data['data']['entries']) == 0:
						break
					myoffset = self.apicache_processor(myoffset, objectType, response_data['data']['entries'], myCache, self.file_refresh_interval)

		elif objectType == "live":
			while True:
				(ret, response_code, response_data) = self.hx_api_object.restListDataAcquisitions(offset=myoffset, sort_term="_id+ascending", limit=self.live_objects_per_poll)
				if ret:
					if len(response_data['data']['entries']) == 0:
						break
					myoffset = self.apicache_processor(myoffset, objectType, response_data['data']['entries'], myCache, self.live_refresh_interval)

		return True

