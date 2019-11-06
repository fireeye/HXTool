#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hxtool_logging
import hxtool_global
import time
from hx_lib import *
from hxtool_scheduler import *
from hxtool_db import *

class hxtool_api_cache:
	def __init__(self, hx_api_object, profile_id, fetcher_interval, objects_per_poll, refresh_interval):
		self.logger = hxtool_logging.getLogger(__name__)
		self.hx_api_object = hx_api_object
		self.profile_id = profile_id
		
		self.fetcher_interval = fetcher_interval
		self.objects_per_poll = objects_per_poll
		self.refresh_interval = refresh_interval

		self.cacheObjects = ["host"]

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

		# TEMP: drop cache
		hxtool_global.hxtool_db.cacheDrop(self.profile_id)

		# Schedule fetcher
		apicache_fetcher_task = hxtool_scheduler_task("System", "Cache fetcher for " + str(self.profile_id), immutable=True)
		apicache_fetcher_task.set_schedule(seconds=self.fetcher_interval)
		apicache_fetcher_task.add_step(self, "apicache_fetcher")
		hxtool_global.hxtool_scheduler.add(apicache_fetcher_task)
		self.logger.info("Apicache fetcher started for profile: {}.".format(self.profile_id))


	def apicache_fetcher(self):
		#self.logger.info("Apicache fetcher called.")
		#Temp workaround
		time.sleep(2)

		for objectType in self.cacheObjects:
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
					(ret, response_code, response_data) = self.hx_api_object.restListHosts(offset=myoffset, sort_term="_id+ascending", limit=self.objects_per_poll)
					if ret:
						# Leave loop if no new records are returned
						if len(response_data['data']['entries']) == 0:
							break

						# Loop over all the records returned
						for host in response_data['data']['entries']:
							myoffset += 1
							
							if host['_id'] in myCache.keys():
								# Record exists, check last update timestamp and update if required
								t = datetime.datetime.now() - datetime.datetime.strptime(myCache[host['_id']], "%Y-%m-%d %H:%M:%S")
								if t.seconds > self.refresh_interval:
									hxtool_global.hxtool_db.cacheUpdate(self.profile_id, "host", host['_id'], host)
									self.logger.debug("{}: Host record updated: {}".format(self.profile_id, host['_id']))

									# For hosts, we also update sysinfo
									(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(host['_id'])
									if ret:
										hxtool_global.hxtool_db.cacheUpdate(self.profile_id, "sysinfo", host['_id'], response_data['data'])
										self.logger.debug("{}: Host sysinfo record updated: {}".format(self.profile_id, host['_id']))
							else:
								# No record exists, create a new entry
								hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, host)
								self.logger.debug("{}: New host added: {}".format(self.profile_id, host['_id']))

								# For hosts, also get sysinfo
								(ret, response_code, response_data) = self.hx_api_object.restGetHostSysinfo(host['_id'])
								if ret:
									hxtool_global.hxtool_db.cacheAddById(self.profile_id, "sysinfo", host['_id'], response_data['data'])
									self.logger.debug("{}: New host sysinfo added: {}".format(self.profile_id, host['_id']))

		
#				elif objectType == "alert":
#					(ret, response_code, response_data) = self.hx_api_object.restGetAlerts(offset=myoffset, limit=self.objects_per_poll)
#					if ret:
#						for alert in response_data['data']['entries']:
#							myoffset += 1
#							hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, alert)
#							self.logger.debug("{}: New alert added: {}".format(self.profile_id, alert['_id']))
#				elif objectType == "triage":
#					(ret, response_code, response_data) = self.hx_api_object.restListTriages(offset=myoffset, limit=self.objects_per_poll)
#					if ret:
#						for triage in response_data['data']['entries']:
#							myoffset += 1
#							hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, triage)
#							self.logger.debug("{}: New triage added: {}".format(self.profile_id, triage['_id']))
#				elif objectType == "file":
#					(ret, response_code, response_data) = self.hx_api_object.restListFileaq(offset=myoffset, limit=self.objects_per_poll)
#					if ret:
#						for file in response_data['data']['entries']:
#							myoffset += 1
#							hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, file)
#							self.logger.debug("{}: New fileacq added: {}".format(self.profile_id, file['_id']))
#				elif objectType == "live":
#					(ret, response_code, response_data) = self.hx_api_object.restListDataAcquisitions(offset=myoffset, limit=self.objects_per_poll)
#					if ret:
#						for live in response_data['data']['entries']:
#							myoffset += 1
#							hxtool_global.hxtool_db.cacheAdd(self.profile_id, objectType, myoffset, live)
#							self.logger.debug("{}: New live acquisition added: {}".format(self.profile_id, live['_id']))
		return True

