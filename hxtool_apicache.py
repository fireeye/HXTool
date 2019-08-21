#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_global
from hx_lib import *
from hxtool_scheduler import *
from hxtool_db import *

class hxtool_api_cache:
	def __init__(self, hx_api_object, profile_id, fetcher_interval, updater_interval, objects_per_poll, max_refresh_per_run, refresh_interval, logger = hxtool_global.get_logger(__name__)):
		self.logger = logger
		self.hx_api_object = hx_api_object
		self.profile_id = profile_id
		
		self.fetcher_interval = fetcher_interval
		self.updater_interval = updater_interval

		self.objects_per_poll = objects_per_poll
		self.max_refresh_per_run = max_refresh_per_run
		self.refresh_interval = refresh_interval

		self.cacheObjects = ["hosts", "alerts"]

		# TEMP: drop cache
		#hxtool_global.hxtool_db.cacheDrop(self.profile_id)

		# Schedule fetcher
		apicache_fetcher_task = hxtool_scheduler_task("System", "Cache fetcher", immutable=True)
		apicache_fetcher_task.set_schedule(seconds=self.fetcher_interval)
		apicache_fetcher_task.add_step(self, "apicache_fetcher")
		hxtool_global.hxtool_scheduler.add(apicache_fetcher_task)
		self.logger.info("Apicache fetcher started for profile: {}".format(self.profile_id))

		# Schedule updater
		apicache_updater_task = hxtool_scheduler_task("System", "Cache updater", immutable=True)
		apicache_updater_task.set_schedule(seconds=self.updater_interval)
		apicache_updater_task.add_step(self, "apicache_updater")
		hxtool_global.hxtool_scheduler.add(apicache_updater_task)
		self.logger.info("Apicache updater started for profile: {}".format(self.profile_id))

	def apicache_fetcher(self):
		#self.logger.info("Apicache fetcher called.")

		for objectType in self.cacheObjects:
			# Check if there are entries for this type and profile
			res = hxtool_global.hxtool_db.cacheList(self.profile_id, objectType)

			if len(res) == 0:
				# No cache entries, start from scratch
				myoffset = 0
			else:
				# We have cache entries, start from last offset
				myoffset = res[-1]['offset']

			if objectType == "hosts":
				(ret, response_code, response_data) = self.hx_api_object.restListHosts(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for host in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, host)

						# For hosts also grab and cache sysinfo
						(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(host['_id'])
						if ret:
							hxtool_global.hxtool_db.cacheAddSysinfo(self.profile_id, "sysinfo", host['_id'], response_data['data'])

						self.logger.info("{}: New host added: {}".format(self.profile_id, host['_id']))
			elif objectType == "alerts":
				(ret, response_code, response_data) = self.hx_api_object.restGetAlerts(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for alert in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, alert)
						self.logger.info("{}: New alert added: {}".format(self.profile_id, alert['_id']))
		return True

	def apicache_updater(self):
		#self.logger.info("Apicache updater called.")

		for objectType in self.cacheObjects:
			update_count = 0
			res = hxtool_global.hxtool_db.cacheList(self.profile_id, objectType)

			for item in res:
				t = datetime.datetime.now() - datetime.datetime.strptime(item['update_timestamp'], "%Y-%m-%d %H:%M:%S")
				if t.seconds > self.refresh_interval:
					update_count += 1

					if update_count > self.max_refresh_per_run:
						break

					if item['type'] == "hosts":
						restUrl = ("/hx/api/v3/hosts/" + str(item['contentId']))
					elif item['type'] == "alerts":
						restUrl = ("/hx/api/v3/alerts/" + str(item['contentId']))
					
					(ret, response_code, response_data) = self.hx_api_object.restGetUrl(restUrl)
					if ret:
						self.logger.info("{}: Updating cache entry: {}, id: {}".format(self.profile_id, item['type'], item['contentId']))
						hxtool_global.hxtool_db.cacheUpdate(item['profile_id'], item['type'], item['offset'], response_data['data'])
						if item['type'] == "hosts":
							(sret, sresponse_code, sresponse_data) = self.hx_api_object.restGetHostSysinfo(item['contentId'])
							if sret:
								self.logger.info("{}: Updating cache entry sysinfo: {}".format(self.profile_id, item['contentId']))
								hxtool_global.hxtool_db.cacheUpdateSysinfo(item['profile_id'], item['type'], item['contentId'], sresponse_data['data'])


		return True
