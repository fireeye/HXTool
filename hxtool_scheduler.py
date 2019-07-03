#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import threading
import datetime
import calendar
import random
from multiprocessing.pool import ThreadPool
from multiprocessing import cpu_count

try:
	import Queue as queue
except ImportError:
	import queue

import hxtool_global
from hx_lib import HXAPI
import hxtool_task_modules
from hxtool_util import *

TASK_STATE_SCHEDULED = 0
TASK_STATE_QUEUED = 1
TASK_STATE_RUNNING = 2
TASK_STATE_COMPLETE = 3
TASK_STATE_STOPPED = 4
TASK_STATE_FAILED = 5

task_state_description = {
	TASK_STATE_SCHEDULED: "Scheduled",
	TASK_STATE_QUEUED 	: "Queued",
	TASK_STATE_RUNNING	: "Running",
	TASK_STATE_COMPLETE : "Complete",
	TASK_STATE_STOPPED	: "Stopped",
	TASK_STATE_FAILED	: "Failed"
}


# Special task indicator that we need to exit now
SIGINT_TASK_ID = -1

MAX_HISTORY_QUEUE_LENGTH = 1000
		
# Note: scheduler resolution is a little less than a second
class hxtool_scheduler:
	def __init__(self, thread_count = None, logger = hxtool_global.get_logger(__name__)):
		self.logger = logger
		self._lock = threading.Lock()
		self.task_queue = {}
		self.history_queue = {}
		self._poll_thread = threading.Thread(target = self._scan_task_queue, name = "PollThread")
		self._stop_event = threading.Event()
		# Allow for thread oversubscription based on CPU count
		self.thread_count = thread_count or (cpu_count() * 4)
		self.task_threads = ThreadPool(self.thread_count)
		self.logger.info("Task scheduler initialized.")

	def _scan_task_queue(self):
		while not self._stop_event.is_set():
			with self._lock:
				self.task_threads.imap_unordered(self._run_task, [_ for _ in self.task_queue.values() if _.should_run()], int(self.thread_count / 1.5))
			self._stop_event.wait(.1)
	
	def _run_task(self, task):
		task.set_state(TASK_STATE_QUEUED)
		self.logger.debug("Executing task with id: %s, name: %s.", task.task_id, task.name)
		try:
			ret = task.run()
		except Exception as e:
			self.logger.error(pretty_exceptions(e))
			task.set_state(TASK_STATE_FAILED)
		
	def start(self):
		self._poll_thread.start()
		self.logger.info("Task scheduler started.")
		
	def stop(self):
		self.logger.debug('stop() enter.')
		self._stop_event.set()
		self.task_threads.close()
		self.task_threads.join()	
		self.logger.debug('stop() exit.')
	
	def signal_child_tasks(self, parent_task_id, parent_task_state, parent_stored_result):
		with self._lock:
			for task_id in self.task_queue:
				self.task_queue[task_id].parent_state_callback(parent_task_id, parent_task_state, parent_stored_result)
	
	def add(self, task, should_store = True):
		with self._lock:
			self.task_queue[task.task_id] = task
			task.set_state(TASK_STATE_SCHEDULED)
			# Note: this must be within the lock otherwise we run into a nasty race condition where the task runs before the stored state is set -
			# with the run lock taking precedence.
			if should_store:	
				task.store()
		return task.task_id	
		
	def add_list(self, tasks):
		if isinstance(tasks, list):
			for t in tasks:
				self.add(t)
		
	def remove(self, task_id):
		if task_id:
			with self._lock:
				if task_id in self.history_queue:
						del self.history_queue[task_id]
						
				t = self.task_queue.get(task_id, None)
				if t and not t.immutable:
					t.stop()
					del self.task_queue[task_id]
					self.logger.debug("Deleting task_id = {} from DB".format(task_id))
					hxtool_global.hxtool_db.taskDelete(t.profile_id, task_id)
			t = None
	
	def get(self, task_id):
		with self._lock:
			return self.task_queue.get(task_id, None)

	def move_to_history(self, task_id):
		with self._lock:
			# Prevent erroring out from a race condition where the task is pending deletion
			if task_id in self.task_queue:
				self.history_queue[task_id] = self.task_queue.pop(task_id).metadata()
		if len(self.history_queue) > MAX_HISTORY_QUEUE_LENGTH:
			self.history_queue.popitem()
	
	def tasks(self):
		# Shallow copy to avoid locking
		if type(self.task_queue.values()) is list:
			q = self.task_queue.values()[:]
		else:
			q = list(self.task_queue.values())
		return [_.metadata() for _ in q] + list(self.history_queue.values())
	
	# Load queued tasks from the database
	def load_from_database(self):
		if self.status():
			tasks = hxtool_global.hxtool_db.taskList()
			for task_entry in tasks:
				p_id = task_entry.get('parent_id', None)
				if p_id and (not task_entry['parent_complete'] and not hxtool_global.hxtool_db.taskGet(task_entry['profile_id'], p_id)):
					self.logger.warn("Deleting orphan task {}, {}".format(task_entry['name'], task_entry['task_id']))
					hxtool_global.hxtool_db.taskDelete(task_entry['profile_id'], task_entry['task_id'])
				else:
					task = hxtool_scheduler_task.deserialize(task_entry)
					task.set_stored()
					# Set should_store to False as we've already been stored, and we skip a needless update
					self.add(task, should_store = False)
		else:
			self.logger.warn("Task scheduler must be running before loading queued tasks from the database.")
	
	def status(self):
		return self._poll_thread.is_alive()
		
class hxtool_scheduler_task:
	def __init__(self, profile_id, name, task_id = None, start_time = None, end_time = None, next_run = None, enabled = True, immutable = False, stop_on_fail = True, parent_id = None, wait_for_parent = True, defer_interval = 30, logger = hxtool_global.get_logger(__name__)):
		
		self.logger = logger
		self._lock = threading.Lock()
		self.profile_id = profile_id
		self.profile_name = "Unknown"
		self.task_id = task_id or str(secure_uuid4())
		self.parent_id = parent_id
		self.wait_for_parent = wait_for_parent
		self.parent_complete = False
		self.name = name
		self.enabled = enabled
		self.immutable = immutable
		self.state = None
		self.last_run_state = None
		self.schedule = {}
		self.start_time = start_time or datetime.datetime.utcnow().replace(microsecond=1)
		self.end_time = end_time
		self.last_run = None
		if parent_id and wait_for_parent:
			self.next_run = None
		else:
			self.next_run = next_run or self.start_time			
		self.stop_on_fail = stop_on_fail
		self.steps = []
		self.stored_result = {}
		self.defer_interval = defer_interval
		
		self._stored = False
		self._stop_signal = False
		self._defer_signal = False
		
		profile = hxtool_global.hxtool_db.profileGet(self.profile_id)
		if profile is not None:
			self.profile_name = profile['hx_name']

	def _calculate_next_run(self):
		self.next_run = None
		
		# Bail out if we've failed and should stop running further
		if self.state == TASK_STATE_FAILED and self.stop_on_fail:
			return
	
		if self._defer_signal:
			# Add some random seconds to the interval to keep the task threads from deadlocking
			self.next_run = (self.last_run + datetime.timedelta(seconds = (self.defer_interval + random.randint(1, 15))))
		# We've never run before because we we're waiting on the parent task to complete
		elif not self.last_run and self.parent_id and self.parent_complete:
			# Add some random seconds to the interval to keep the task threads from deadlocking
			self.next_run = (datetime.datetime.utcnow() + datetime.timedelta(seconds = (self.defer_interval + random.randint(1, 15))))
		elif self.schedule and ((not self.end_time) or (self.end_time and (self.end_time < datetime.datetime.utcnow()))):
			if self.schedule.get('day_of_month', None):
				n_month = self.last_run.month
				n_year = self.last_run.year
				if n_month == 12:
					n_month = 1
					n_year += 1
				else:
					n_month += 1
				self.next_run = self.last_run.replace(year = n_year, month = n_month)	
			else:
				if self.schedule.get('day_of_week', None):
					self.next_run = self.last_run + datetime.timedelta(days = 7)
				elif self.schedule.get('hours', None):
					self.next_run = self.last_run + datetime.timedelta(hours = self.schedule['hours'])
				elif self.schedule.get('minutes', None): 
					self.next_run = self.last_run + datetime.timedelta(minutes = self.schedule['minutes'])			

	def set_schedule(self, minutes = None, hours = None, day_of_week = None, day_of_month = None):
		with self._lock:
			self.schedule = {
				'minutes' : int(minutes) if minutes else None,
				'hours' : int(hours) if hours else None,
				'day_of_week' : int(day_of_week) if day_of_week else None,
				'day_of_month' : int(day_of_month) if day_of_month else None
			}
			
			# Reset microseconds to keep things from drifting
			now = datetime.datetime.utcnow().replace(microsecond=1)
		
			# First figure out the delta to the start time 
			# For hours and minutes, use a relative value (i.e. current time + hours + minutes), whereas for
			# day of week and day of month, use absolute values for hour and minute.
		
			n_seconds = 0	
			n_minutes = self.schedule['minutes'] or 0
			n_hours = self.schedule['hours'] or 0
			n_days = 0
			
			if day_of_week or day_of_month:
				n_seconds = (60 - now.second)
				n_minutes = (59 - now.minute) + n_minutes
				n_hours = (23 - now.hour) + n_hours	
			if day_of_week:
				n_days = (6 - now.weekday()) + self.schedule['day_of_week']
			if day_of_month:
				n_days = (datetime.date(now.year if now.month < 12 else now.year + 1, now.month + 1 if now.month < 12 else 1, self.schedule['day_of_month']) - now.date()).days - 1
		
			self.next_run = now + datetime.timedelta(seconds = n_seconds, minutes = n_minutes, hours = n_hours, days = n_days)
			# TODO: we shouldn't clobber this in a case of where we change an existing tasks schedule
			self.start_time = self.next_run
	
	def should_run(self):
		return (self.next_run and
				self.enabled and  
				self.state == TASK_STATE_SCHEDULED and
				(self.parent_complete if self.parent_id and self.wait_for_parent else True) and	
				datetime.datetime.utcnow() >= self.next_run)
					
	def add_step(self, module, func = "run", args = (), kwargs = {}):
		# This is an HXTool task module, we need to init it.
		if hasattr(module, 'hxtool_task_module'):
			module = module(self)
		with self._lock:
			self.steps.append((module, func, args, kwargs))
		
	# Use this to set state, its thread-safe
	def set_state(self, state):
		with self._lock:
			self.state = state
			
	def set_stored(self, stored = True):
		with self._lock:
			self._stored = stored
		
	def run(self):
		self._stop_signal = False
		self._defer_signal = False
		ret = False
		
		if self.enabled:
			
			with self._lock:
				
				self.state = TASK_STATE_RUNNING
				
				# Reset microseconds to keep from drifting too badly
				self.last_run = datetime.datetime.utcnow().replace(microsecond=1)
				
				for module, func, args, kwargs in self.steps:
					self.logger.debug("Have module: {}, function: {}".format(module.__module__, func))
					if getattr(module, 'hxtool_task_module', lambda: False)():
						if module.enabled == False:
							self.logger.error("Module {} is disabled!".format(module.__module__))
							ret = False
							self.state = TASK_STATE_FAILED
							break
							
						for arg_i in module.input_args():
							if not kwargs.get(arg_i['name'], None):
								if arg_i['name'] in self.stored_result.keys():
									kwargs[arg_i['name']] = self.stored_result[arg_i['name']]
								elif arg_i['required']:
									self.logger.error("Module {} requires argument {} that was not found! Bailing!".format(module.__module__, arg_i['name']))
									ret = False
									self.state = TASK_STATE_FAILED
									break
				
					if self.state != TASK_STATE_FAILED:
						self.logger.debug("Begin execute {}.{}".format(module.__module__, func))
						result = getattr(module, func)(*args, **kwargs)
						self.logger.debug("End execute {}.{}".format(module.__module__, func))
						if isinstance(result, tuple) and len(result) > 1:
							ret = result[0]
							# Store the result - make sure it is of type dict
							if isinstance(result[1], dict):
								# Use update so we don't clobber existing values
								self.stored_result.update(result[1])
							elif result[1] != None:
								self.logger.error("Task module {} returned a value that was not a dictionary or None. Discarding the result.".format(module.__module__))
						else:
							ret = result
						
						
						if self._defer_signal:
							break
						elif self._stop_signal:
							self.state = TASK_STATE_STOPPED
							break
						elif not ret and self.stop_on_fail:
							self.state = TASK_STATE_FAILED
							break
				
				self._calculate_next_run()
				
				if self.next_run:
					self.last_run_state = self.state
					self.state = TASK_STATE_SCHEDULED
					if not self._defer_signal:
						# Reset parent_complete for recurring tasks
						self.parent_complete = False
				elif self.state < TASK_STATE_STOPPED:
					self.state = TASK_STATE_COMPLETE
				
				# Support test harness
				if hasattr(hxtool_global, 'hxtool_scheduler'):
					hxtool_global.hxtool_scheduler.signal_child_tasks(self.task_id, self.state, self.stored_result)
		else:
			self.set_state(TASK_STATE_STOPPED)
		
		if self.state != TASK_STATE_SCHEDULED and self._stored:
			self.logger.debug("Deleting task_id = {} from DB".format(self.task_id))
			hxtool_global.hxtool_db.taskDelete(self.profile_id, self.task_id)
			self.set_stored(stored = False)
			hxtool_global.hxtool_scheduler.move_to_history(self.task_id)
		else:
			self.store()
				
		return ret

	def parent_state_callback(self, parent_task_id, parent_state, parent_stored_result):
		if self.parent_id and self.parent_id == parent_task_id:
			self.logger.debug("parent_state_callback(): task_id = {}, parent_id = {}, parent_state = {}".format(self.task_id, parent_task_id, parent_state))
			if parent_state == TASK_STATE_COMPLETE:
				self.logger.debug("Received signal that parent task is complete.")
				with self._lock:
					self.stored_result = parent_stored_result
					self.parent_complete = True
					# Now that the parent is complete set the next run
					self._calculate_next_run()
			elif parent_state == TASK_STATE_STOPPED:
				self.stop()
			elif parent_state == TASK_STATE_FAILED:
				self.set_state(TASK_STATE_FAILED)
			
			# Make sure we store the updated state
			self.store()
			
			self.logger.debug("name = {}, next_run = {}".format(self.name, self.next_run))

				
	def stop(self):
		self._stop_signal = True
	
	def defer(self):
		self._defer_signal = True
			
	def store(self):
		if not (self.immutable or self._stored):
			hxtool_global.hxtool_db.taskCreate(self.serialize())
			self.set_stored()
		elif self._stored:
			hxtool_global.hxtool_db.taskUpdate(self.profile_id, self.task_id, self.serialize())
	
	def metadata(self):
		return self.serialize(include_module_data = False)
		
	def serialize(self, include_module_data = True):
		r = {
			'profile_id' : self.profile_id,
			'profile_name' : self.profile_name,
			'task_id' : self.task_id,
			'name' : self.name,
			'schedule' : self.schedule,
			'start_time' : str(self.start_time),
			'end_time' : str(self.end_time) if self.end_time else None,
			'last_run' : str(self.last_run) if self.last_run else None,
			'next_run' : str(self.next_run) if self.next_run else None,
			'enabled' : self.enabled,
			'immutable' : self.immutable,
			'stop_on_fail' : self.stop_on_fail,
			'parent_id' : self.parent_id,
			'parent_complete' : self.parent_complete,
			'wait_for_parent' : self.wait_for_parent,
			'defer_interval' : self.defer_interval,
			'state' : self.state,
			'last_run_state' : self.last_run_state,
		}
		if include_module_data:
			r['stored_result'] = self.stored_result
			r['steps'] = [{ 
						'module' : m.__module__,
						'function' : f,
						'args' : a,
						'kwargs' : ka
						}
						for m, f, a, ka in self.steps
			]
		return r	
	
	@staticmethod	
	def deserialize(d):
		task = hxtool_scheduler_task(d['profile_id'],
									d['name'],
									task_id = d['task_id'],
									parent_id = d.get('parent_id', None),
									wait_for_parent = d.get('wait_for_parent', True),
									start_time = HXAPI.dt_from_str(d['start_time']),
									end_time = HXAPI.dt_from_str(d['end_time']) if d['end_time'] else None,
									next_run = HXAPI.dt_from_str(d['next_run']) if d['next_run'] else None,
									enabled = d['enabled'],
									immutable = d['immutable'],
									stop_on_fail = d['stop_on_fail'],
									defer_interval = d['defer_interval'])
		task.last_run = d.get('last_run', None)
		task.parent_complete = d.get('parent_complete', False)
		task.last_run_state = d.get('last_run_state', None)							
		task.state = d.get('state')
		schedule = d.get('schedule', None)
		if schedule:
			task.set_schedule(**schedule)
		else:
			task._calculate_next_run()
		for s in d['steps']:
			# I hate this
			step_module = eval(s['module'])
			task.add_step(step_module, s['function'], s['args'], s['kwargs'])
		return task
									
									
		