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

		self.cacheObjects = ["host", "alert", "triage", "file", "live"]

		# Number of objects that can be fetched per second
		self.fetcher_capability = self.objects_per_poll // self.fetcher_interval

		# Number of updater polls that can be made during the refresh_interval
		self.updater_capability_attempts = self.refresh_interval // self.updater_interval

		# Number of records that can be updated within the refresh_interval
		self.updater_capability = self.updater_capability_attempts * self.max_refresh_per_run

		# Tell hxtool_global about our stats
		hxtool_global.apicache = {}
		hxtool_global.apicache['fetcher_capability'] = self.fetcher_capability
		hxtool_global.apicache['updater_capability'] = self.updater_capability
		hxtool_global.apicache['updater_capability_attempts'] = self.updater_capability_attempts

		# TEMP: drop cache
		#hxtool_global.hxtool_db.cacheDrop(self.profile_id)

		# Schedule fetcher
		apicache_fetcher_task = hxtool_scheduler_task("System", "Cache fetcher for " + str(self.profile_id), immutable=True)
		apicache_fetcher_task.set_schedule(seconds=self.fetcher_interval)
		apicache_fetcher_task.add_step(self, "apicache_fetcher")
		hxtool_global.hxtool_scheduler.add(apicache_fetcher_task)
		self.logger.info("Apicache fetcher started for profile: {}. Capacity: {} records per second".format(self.profile_id, self.fetcher_capability))

		# Schedule updater
		apicache_updater_task = hxtool_scheduler_task("System", "Cache updater for " + str(self.profile_id), immutable=True)
		apicache_updater_task.set_schedule(seconds=self.updater_interval)
		apicache_updater_task.add_step(self, "apicache_updater")
		hxtool_global.hxtool_scheduler.add(apicache_updater_task)
		self.logger.info("Apicache updater started for profile: {}. Capacity: {} records can be updated within the refresh interval".format(self.profile_id, self.updater_capability))

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

			hxtool_global.apicache['fetcher_last_entry'] = res[-1]

			if objectType == "host":
				(ret, response_code, response_data) = self.hx_api_object.restListHosts(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for host in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, host)

						# For hosts also grab and cache sysinfo
						(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(host['_id'])
						if ret:
							hxtool_global.hxtool_db.cacheAddSysinfo(self.profile_id, "sysinfo", host['_id'], response_data['data'])

						self.logger.debug("{}: New host added: {}".format(self.profile_id, host['_id']))
			elif objectType == "alert":
				(ret, response_code, response_data) = self.hx_api_object.restGetAlerts(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for alert in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, alert)
						self.logger.debug("{}: New alert added: {}".format(self.profile_id, alert['_id']))
			elif objectType == "triage":
				(ret, response_code, response_data) = self.hx_api_object.restListTriages(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for triage in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, triage)
						self.logger.debug("{}: New triage added: {}".format(self.profile_id, triage['_id']))
			elif objectType == "file":
				(ret, response_code, response_data) = self.hx_api_object.restListFileaq(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for file in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, file)
						self.logger.debug("{}: New fileacq added: {}".format(self.profile_id, file['_id']))
			elif objectType == "live":
				(ret, response_code, response_data) = self.hx_api_object.restListDataAcquisitions(offset=myoffset, limit=self.objects_per_poll)
				if ret:
					for live in response_data['data']['entries']:
						myoffset += 1
						hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, live)
						self.logger.debug("{}: New live acquisition added: {}".format(self.profile_id, live['_id']))


		return True

	def apicache_updater(self):
		#self.logger.info("Apicache updater called.")

		for objectType in self.cacheObjects:
			update_count = 0
			res = hxtool_global.hxtool_db.cacheListUpdate(self.profile_id, objectType)

			for item in res:
				t = datetime.datetime.now() - datetime.datetime.strptime(item['update_timestamp'], "%Y-%m-%d %H:%M:%S")
				if t.seconds > self.refresh_interval:
					update_count += 1

					if update_count > self.max_refresh_per_run:
						break

					if item['type'] == "host":
						restUrl = ("/hx/api/v3/hosts/" + str(item['contentId']))
					elif item['type'] == "alert":
						restUrl = ("/hx/api/v3/alerts/" + str(item['contentId']))
					elif item['type'] == "triage":
						restUrl = ("/hx/api/v3/acqs/triages/" + str(item['contentId']))
					elif item['type'] == "file":
						restUrl = ("/hx/api/v3/acqs/files/" + str(item['contentId']))
					elif item['type'] == "live":
						restUrl = ("/hx/api/v3/acqs/live/" + str(item['contentId']))

					(ret, response_code, response_data) = self.hx_api_object.restGetUrl(restUrl)
					if ret:
						if response_code == 200:
							self.logger.debug("{}: Updating cache entry: {}, id: {}".format(self.profile_id, item['type'], item['contentId']))
							hxtool_global.hxtool_db.cacheUpdate(item['profile_id'], item['type'], item['offset'], response_data['data'])
							if item['type'] == "host":
								(sret, sresponse_code, sresponse_data) = self.hx_api_object.restGetHostSysinfo(item['contentId'])
								if sret:
									self.logger.debug("{}: Updating cache entry sysinfo: {}".format(self.profile_id, item['contentId']))
									hxtool_global.hxtool_db.cacheUpdateSysinfo(item['profile_id'], "sysinfo", item['contentId'], sresponse_data['data'])
								else:
									pass
						else:
							pass
					else:
						if response_code == 404:
							# Need to flag this entry as deleted since it's not on the controller anymore
							self.logger.debug("{}: Flagging entry: {}, id: {} as removed".format(self.profile_id, item['type'], item['contentId']))
							hxtool_global.hxtool_db.cacheFlagRemove(item['profile_id'], item['type'], item['offset'])
							if item['type'] == "host":
								hxtool_global.hxtool_db.cacheFlagRemove(item['profile_id'], "sysinfo", item['contentId'])
						else:
							pass

				hxtool_global.apicache['updater_last_entry'] = item
				
		return True
