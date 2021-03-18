#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import datetime
import random

import hxtool_logging
import hxtool_global
# TODO: figure out how to remove this, need to remove the eval() from deserialize
import hxtool_task_modules
from hxtool_util import secure_uuid4
from hx_lib import HXAPI

logger = hxtool_logging.getLogger(__name__)

class task_states(object):
	TASK_STATE_SCHEDULED = 0
	TASK_STATE_QUEUED = 1
	TASK_STATE_RUNNING = 2
	TASK_STATE_COMPLETE = 3
	TASK_STATE_STOPPED = 4
	TASK_STATE_FAILED = 5
	TASK_STATE_PENDING_DELETION = 6
	
	description = {
		TASK_STATE_SCHEDULED: "Scheduled",
		TASK_STATE_QUEUED 	: "Queued",
		TASK_STATE_RUNNING	: "Running",
		TASK_STATE_COMPLETE : "Complete",
		TASK_STATE_STOPPED	: "Stopped",
		TASK_STATE_FAILED	: "Failed",
		TASK_STATE_PENDING_DELETION	: "Pending Deletion"
	}
		

class hxtool_scheduler_task:
	def __init__(self, profile_id, name, task_id = None, start_time = None, end_time = None, next_run = None, enabled = True, immutable = False, stop_on_fail = True, parent_id = None, wait_for_parent = True, defer_interval = 30):
		
		self._lock = threading.Lock()
		self.profile_id = profile_id
		self.profile_name = "Unknown"
		self.task_id = task_id or str(secure_uuid4())
		self.parent_id = parent_id
		self.scheduler = None
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
		if self.state == task_states.TASK_STATE_PENDING_DELETION or (self.state == task_states.TASK_STATE_FAILED and self.stop_on_fail):
			return
		elif self.state == task_states.TASK_STATE_QUEUED or self.state == task_states.TASK_STATE_RUNNING:
			logger.critical("Task ID {} calculating next run while still running, this should never happen!".format(self.task_id))
	
		# Reset microseconds to keep things from drifting
		now = datetime.datetime.utcnow().replace(microsecond=1)
	
		if self._defer_signal:
			# Add some random seconds to the interval to keep the task threads from deadlocking
			self.next_run = (self.last_run + datetime.timedelta(seconds = (self.defer_interval + random.randint(1, 15))))
		# We've never run before because we we're waiting on the parent task to complete
		elif not self.last_run and self.parent_id and self.parent_complete:
			# Add some random seconds to the interval to keep the task threads from deadlocking
			self.next_run = (now + datetime.timedelta(seconds = (self.defer_interval + random.randint(1, 15))))
		elif self.schedule and ((not self.end_time) or (self.end_time and (self.end_time < now))):
			self.next_run = self.last_run + datetime.timedelta(
				weeks = self.schedule['weeks'],
				days = self.schedule['days'],
				hours = self.schedule['hours'],
				minutes = self.schedule['minutes'],
				seconds = self.schedule['seconds']
			)
			
	def set_schedule(self, seconds = 0, minutes = 0, hours = 0, days = 0, weeks = 0):
		with self._lock:
			self.schedule = {
				'seconds' : int(seconds),
				'minutes' : int(minutes),
				'hours' : int(hours),
				'days' : int(days),
				'weeks': int(weeks)
			}
			
	def should_run(self):
		return (
				self.enabled and
				self.state is task_states.TASK_STATE_SCHEDULED and
				self.next_run is not None and
				datetime.datetime.utcnow() >= self.next_run and
				(self.parent_complete if self.parent_id is not None and self.wait_for_parent else True)
		)

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
		
	def run(self, scheduler):
		self._stop_signal = False
		self._defer_signal = False
		self._pending_deletion_signal = False
		ret = False
		
		if self.enabled:
			
			with self._lock:
				
				self.state = task_states.TASK_STATE_RUNNING
				
				self.scheduler = scheduler
				
				# Reset microseconds to keep from drifting too badly
				self.last_run = datetime.datetime.utcnow().replace(microsecond=1)
				# Clear this, otherwise the task view looks confusing
				self.next_run = None
				
				for module, func, args, kwargs in self.steps:
					logger.debug("Have module: {}, function: {}".format(module.__module__, func))
					if getattr(module, 'hxtool_task_module', lambda: False)():
						if module.enabled == False:
							logger.error("Module {} is disabled!".format(module.__module__))
							ret = False
							self.state = task_states.TASK_STATE_FAILED
							break
							
						for arg_i in module.input_args():
							if not kwargs.get(arg_i['name'], None):
								if arg_i['name'] in self.stored_result.keys():
									kwargs[arg_i['name']] = self.stored_result[arg_i['name']]
								elif arg_i['required']:
									logger.error("Module {} requires argument {} that was not found! Bailing!".format(module.__module__, arg_i['name']))
									ret = False
									self.state = task_states.TASK_STATE_FAILED
									break
					if self.state != task_states.TASK_STATE_FAILED:
						logger.debug("Begin execute {}.{}".format(module.__module__, func))
						result = getattr(module, func)(*args, **kwargs)
						logger.debug("End execute {}.{}".format(module.__module__, func))
						if isinstance(result, tuple) and len(result) > 1:
							ret = result[0]
							# Store the result - make sure it is of type dict
							if isinstance(result[1], dict):
								# Use update so we don't clobber existing values
								self.stored_result.update(result[1])
							elif result[1] is not None:
								logger.error("Task module {} returned a value that was not a dictionary or None. Discarding the result.".format(module.__module__))
						else:
							ret = result
					
					
					if self._defer_signal:
						break
					elif self._stop_signal:
						self.state = task_states.TASK_STATE_STOPPED
						break
					elif self._pending_deletion_signal:
						self.state = task_states.TASK_STATE_PENDING_DELETION
						break
					elif not ret and self.stop_on_fail:
						self.state = task_states.TASK_STATE_FAILED
						break
				
				if self.state < task_states.TASK_STATE_STOPPED:
					self.state = task_states.TASK_STATE_COMPLETE
				
				if not self.parent_id:
					scheduler.signal_child_tasks(self.task_id, self.state, self.stored_result)
				
				self._calculate_next_run()
				
				if self.next_run:
					self.last_run_state = self.state
					self.state = task_states.TASK_STATE_SCHEDULED
					if not self._defer_signal:
						# Reset parent_complete for recurring tasks
						self.parent_complete = False
			
			self.scheduler = None
		else:
			self.set_state(task_states.TASK_STATE_STOPPED)
		
		# Don't delete when task state is TASK_STATE_PENDING_DELETION as the remove() function handles that
		if self.state != task_states.TASK_STATE_SCHEDULED and self._stored:
			self.unstore()
			if self.state != task_states.TASK_STATE_PENDING_DELETION:
				scheduler.move_to_history(self.task_id)
		else:
			self.store()
				
		return ret

	def parent_state_callback(self, parent_task_id, parent_state, parent_stored_result):
		if self.parent_id == parent_task_id:
			logger.debug("parent_state_callback(): task_id = {}, parent_id = {}, parent_state = {}".format(self.task_id, parent_task_id, parent_state))
			if parent_state == task_states.TASK_STATE_COMPLETE:
				logger.debug("Received signal that parent task is complete.")
				with self._lock:
					self.stored_result = parent_stored_result
					self.parent_complete = True
					# Now that the parent is complete set the next run
					self._calculate_next_run()
					# Make sure we store the updated state
					self.store()
			elif parent_state == task_states.TASK_STATE_STOPPED:
				self.stop()
				self.set_state(task_states.TASK_STATE_STOPPED)
			elif parent_state == task_states.TASK_STATE_FAILED:
				self.set_state(task_states.TASK_STATE_FAILED)
			
			logger.debug("name = {}, next_run = {}".format(self.name, self.next_run))

				
	def stop(self):
		self._stop_signal = True
		if self.state != task_states.TASK_STATE_RUNNING:
			self.set_state(task_states.TASK_STATE_STOPPED)
			
	def defer(self):
		self._defer_signal = True
	
	def remove(self):
		self._pending_deletion_signal = True
		if self.state != task_states.TASK_STATE_RUNNING:
			self.set_state(task_states.TASK_STATE_PENDING_DELETION)
			self.unstore()
			
	def store(self):
		if not (self.immutable or self._stored):
			hxtool_global.hxtool_db.taskCreate(self.serialize())
			self.set_stored()
		elif self._stored:
			hxtool_global.hxtool_db.taskUpdate(self.profile_id, self.task_id, self.serialize())
	
	def unstore(self):
		logger.debug("Deleting task_id = {} from DB".format(self.task_id))
		hxtool_global.hxtool_db.taskDelete(self.profile_id, self.task_id)
		self.set_stored(stored = False)
	
	def metadata(self):
		return self.serialize(include_module_data = False)
		
	def serialize(self, include_module_data = True):
		r = {
			'profile_id' : self.profile_id,
			'profile_name' : self.profile_name,
			'task_id' : self.task_id,
			'name' : self.name,
			'schedule' : self.schedule,
			'start_time' : HXAPI.dt_to_str(self.start_time),
			'end_time' : HXAPI.dt_to_str(self.end_time) if self.end_time else None,
			'last_run' : HXAPI.dt_to_str(self.last_run) if self.last_run else None,
			'next_run' : HXAPI.dt_to_str(self.next_run) if self.next_run else None,
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
		task.last_run = HXAPI.dt_from_str(d['last_run']) if d['last_run'] else None
		task.parent_complete = d.get('parent_complete', False)
		task.last_run_state = d.get('last_run_state', None)							
		task.state = d.get('state')
		schedule = d.get('schedule', None)
		if schedule is dict:
			task.set_schedule(**schedule)
			task._calculate_next_run()
		for s in d['steps']:
			# I hate this
			step_module = eval(s['module'])
			task.add_step(step_module, s['function'], s['args'], s['kwargs'])
		return task
									
									
		