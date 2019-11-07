#!/usr/bin/env python
# -*- coding: utf-8 -*-


import threading
import datetime
import calendar
import random
from multiprocessing.pool import ThreadPool
from multiprocessing import cpu_count, TimeoutError

import hxtool_logging
import hxtool_global
from hxtool_vars import default_encoding
from hx_lib import HXAPI
from hxtool_util import *
import hxtool_task_modules


logger = hxtool_logging.getLogger(__name__)

TASK_API_KEY = 'Z\\U+z$B*?AiV^Fr~agyEXL@R[vSTJ%N&'.encode(default_encoding)

TASK_STATE_SCHEDULED = 0
TASK_STATE_QUEUED = 1
TASK_STATE_RUNNING = 2
TASK_STATE_COMPLETE = 3
TASK_STATE_STOPPED = 4
TASK_STATE_FAILED = 5
TASK_STATE_PENDING_DELETION = 6

task_state_description = {
	TASK_STATE_SCHEDULED: "Scheduled",
	TASK_STATE_QUEUED 	: "Queued",
	TASK_STATE_RUNNING	: "Running",
	TASK_STATE_COMPLETE : "Complete",
	TASK_STATE_STOPPED	: "Stopped",
	TASK_STATE_FAILED	: "Failed",
	TASK_STATE_PENDING_DELETION	: "Pending Deletion"
}


MAX_HISTORY_QUEUE_LENGTH = 1000
		
# Note: scheduler resolution is a little less than a second
class hxtool_scheduler:
	def __init__(self, thread_count = None):
		self._lock = threading.Lock()
		self.task_queue = {}
		self.history_queue = {}
		self.task_hx_api_sessions = {}
		self._poll_thread = threading.Thread(target = self._scan_task_queue, name = "PollThread")
		self._stop_event = threading.Event()
		# Allow for thread oversubscription based on CPU count
		self.thread_count = thread_count or (cpu_count() + 1)
		self.task_threads = ThreadPool(self.thread_count)
		logger.info("Task scheduler initialized.")


	def _scan_task_queue(self):
		while not self._stop_event.wait(.1):
			ret = None
			with self._lock:
				ret = self.task_threads.imap_unordered(self._run_task, [_ for _ in self.task_queue.values() if _.should_run()])
			if ret:
				while not self._stop_event.is_set():
					try:
						ret.next(timeout=5)
					except TimeoutError:
						break
					except StopIteration:
						break
					except Exception as e:
						logger.error(pretty_exceptions(e))
						continue
					
	def _run_task(self, task):
		ret = False
		task.set_state(TASK_STATE_QUEUED)
		logger.debug("Executing task with id: %s, name: %s.", task.task_id, task.name)
		try:
			ret = task.run(self)
		except Exception as e:
			logger.error(pretty_exceptions(e))
			task.set_state(TASK_STATE_FAILED)
		finally:
			return ret
			
	def _add_task_api_task(self, profile_id, hx_host, hx_port, username, password):
		self.task_hx_api_sessions[profile_id] = HXAPI(hx_host,
														hx_port = hx_port, 
														proxies = hxtool_global.hxtool_config['network'].get('proxies'), 
														headers = hxtool_global.hxtool_config['headers'], 
														cookies = hxtool_global.hxtool_config['cookies'], 
														logger_name = hxtool_logging.getLoggerName(HXAPI.__name__), 
														default_encoding = default_encoding)
		api_login_task = hxtool_scheduler_task(profile_id, "Task API Login - {}".format(hx_host), immutable = True)
		api_login_task.add_step(hxtool_task_modules.task_api_session_module, kwargs = {
									'profile_id' : profile_id,
									'username' : username,
									'password' : password
		})
		self.add(api_login_task)
	
	def start(self):
		self._poll_thread.start()
		logger.info("Task scheduler started with %s threads.", self.thread_count)
		
	def stop(self):
		logger.debug("stop() enter.")
		self._stop_event.set()
		logger.debug("Closing the task thread pool.")
		self.task_threads.close()
		logger.debug("Waiting for running threads to terminate.")
		self.task_threads.join()
		logger.debug("stop() exit.")
	
	def initialize_task_api_sessions(self):
		# Loop through background credentials and start the API sessions
		profiles = hxtool_global.hxtool_db.profileList()
		for profile in profiles:
			task_api_credential = hxtool_global.hxtool_db.backgroundProcessorCredentialGet(profile['profile_id'])
			if task_api_credential:
				try:
					salt = HXAPI.b64(task_api_credential['salt'], True)
					iv = HXAPI.b64(task_api_credential['iv'], True)
					key = crypt_pbkdf2_hmacsha256(salt, TASK_API_KEY)
					decrypted_background_password = crypt_aes(key, iv, task_api_credential['hx_api_encrypted_password'], decrypt = True)
					self._add_task_api_task(profile['profile_id'], profile['hx_host'], profile['hx_port'], task_api_credential['hx_api_username'], decrypted_background_password) 
					decrypted_background_password = None
				except UnicodeDecodeError:
					logger.error("Please reset the background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
			else:
				logger.info("No background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
	
	def add_task_api_session(self, profile_id, hx_host, hx_port, username, password):
		iv = crypt_generate_random(16)
		salt = crypt_generate_random(32)
		key = crypt_pbkdf2_hmacsha256(salt, TASK_API_KEY)
		encrypted_password = crypt_aes(key, iv, password)
		hxtool_global.hxtool_db.backgroundProcessorCredentialCreate(profile_id, username, HXAPI.b64(iv), HXAPI.b64(salt), encrypted_password)
		encrypted_password = None
		self._add_task_api_task(profile_id, hx_host, hx_port, username, password)
		password = None
	
	def remove_task_api_session(self, profile_id):
		out = hxtool_global.hxtool_db.backgroundProcessorCredentialRemove(profile_id)
		hx_api_object = self.task_hx_api_sessions.get(profile_id)
		if hx_api_object and hx_api_object.restIsSessionValid():
			(ret, response_code, response_data) = hx_api_object.restLogout()
			del self.task_hx_api_sessions[profile_id]
	
	def logout_task_api_sessions(self):
		for hx_api_object in self.task_hx_api_sessions.values():
			if hx_api_object is not None:
				hx_api_object.restLogout()
				hx_api_object = None
	
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
		
	def remove(self, task_id, delete_children=True):
		if task_id:
			with self._lock:
				if delete_children:
					# We need to make a shallow copy so we don't modify the task_queue while iterating over it
					for child_task_id in [_.task_id for _ in self.task_queue.values() if _.parent_id == task_id]:
						self.task_queue[child_task_id].remove()
						del self.task_queue[child_task_id]
							
					for child_task_id in [_['task_id'] for _ in self.history_queue.values() if _['parent_id'] == task_id]:
						del self.history_queue[child_task_id]
							
				t = self.task_queue.get(task_id, None)
				if t and not t.immutable:
					t.remove()
					del self.task_queue[task_id]
					t = None
				elif task_id in self.history_queue:
					del self.history_queue[task_id]
				
	def get(self, task_id):
		with self._lock:
			return self.task_queue.get(task_id, None)

	def move_to_history(self, task_id):
		with self._lock:
			t = self.task_queue.pop(task_id, None)
			if t is not None:
				self.history_queue[task_id] = t.metadata()
		if len(self.history_queue) > MAX_HISTORY_QUEUE_LENGTH:
			self.history_queue.popitem()
	
	def tasks(self):
		# Shallow copy to avoid locking
		return [_.metadata() for _ in list(self.task_queue.values())] + list(self.history_queue.values())
	
	# Load queued tasks from the database
	def load_from_database(self):
		try:
			if self.status():
				tasks = hxtool_global.hxtool_db.taskList()
				for task_entry in tasks:
					p_id = task_entry.get('parent_id', None)
					if p_id and (not task_entry['parent_complete'] and not hxtool_global.hxtool_db.taskGet(task_entry['profile_id'], p_id)):
						logger.warn("Deleting orphan task {}, {}".format(task_entry['name'], task_entry['task_id']))
						hxtool_global.hxtool_db.taskDelete(task_entry['profile_id'], task_entry['task_id'])
					else:
						task = hxtool_scheduler_task.deserialize(task_entry)
						task.set_stored()
						# Set should_store to False as we've already been stored, and we skip a needless update
						self.add(task, should_store = False)
			else:
				logger.warn("Task scheduler must be running before loading queued tasks from the database.")
		except Exception as e:
			logger.error("Failed to load saved tasks from the database. Error: {}".format(pretty_exceptions(e)))
	
	def status(self):
		return self._poll_thread.is_alive()
		
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
		if self.state == TASK_STATE_PENDING_DELETION or (self.state == TASK_STATE_FAILED and self.stop_on_fail):
			return
		elif self.state == TASK_STATE_QUEUED or self.state == TASK_STATE_RUNNING:
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
		return (self.next_run is not None and
				self.enabled and  
				self.state == TASK_STATE_SCHEDULED and
				(self.parent_complete if (self.parent_id and self.wait_for_parent) else True) and
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
		
	def run(self, scheduler):
		self._stop_signal = False
		self._defer_signal = False
		self._pending_deletion_signal = False
		ret = False
		
		if self.enabled:
			
			with self._lock:
				
				self.state = TASK_STATE_RUNNING
				
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
							self.state = TASK_STATE_FAILED
							break
							
						for arg_i in module.input_args():
							if not kwargs.get(arg_i['name'], None):
								if arg_i['name'] in self.stored_result.keys():
									kwargs[arg_i['name']] = self.stored_result[arg_i['name']]
								elif arg_i['required']:
									logger.error("Module {} requires argument {} that was not found! Bailing!".format(module.__module__, arg_i['name']))
									ret = False
									self.state = TASK_STATE_FAILED
									break
					if self.state != TASK_STATE_FAILED:
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
						self.state = TASK_STATE_STOPPED
						break
					elif self._pending_deletion_signal:
						self.state = TASK_STATE_PENDING_DELETION
						break
					elif not ret and self.stop_on_fail:
						self.state = TASK_STATE_FAILED
						break
				
				if self.state < TASK_STATE_STOPPED:
					self.state = TASK_STATE_COMPLETE
				
				if not self.parent_id:
					hxtool_global.hxtool_scheduler.signal_child_tasks(self.task_id, self.state, self.stored_result)
				
				self._calculate_next_run()
				
				if self.next_run:
					self.last_run_state = self.state
					self.state = TASK_STATE_SCHEDULED
					if not self._defer_signal:
						# Reset parent_complete for recurring tasks
						self.parent_complete = False
			
			self.scheduler = None
		else:
			self.set_state(TASK_STATE_STOPPED)
		
		# Don't delete when task state is TASK_STATE_PENDING_DELETION as the remove() function handles that
		if self.state != TASK_STATE_SCHEDULED and self._stored:
			self.unstore()
			if self.state != TASK_STATE_PENDING_DELETION:
				hxtool_global.hxtool_scheduler.move_to_history(self.task_id)
		else:
			self.store()
				
		return ret

	def parent_state_callback(self, parent_task_id, parent_state, parent_stored_result):
		if self.parent_id == parent_task_id:
			logger.debug("parent_state_callback(): task_id = {}, parent_id = {}, parent_state = {}".format(self.task_id, parent_task_id, parent_state))
			if parent_state == TASK_STATE_COMPLETE:
				logger.debug("Received signal that parent task is complete.")
				with self._lock:
					self.stored_result = parent_stored_result
					self.parent_complete = True
					# Now that the parent is complete set the next run
					self._calculate_next_run()
					# Make sure we store the updated state
					self.store()
			elif parent_state == TASK_STATE_STOPPED:
				self.stop()
				self.set_state(TASK_STATE_STOPPED)
			elif parent_state == TASK_STATE_FAILED:
				self.set_state(TASK_STATE_FAILED)
			
			logger.debug("name = {}, next_run = {}".format(self.name, self.next_run))

				
	def stop(self):
		self._stop_signal = True
		if self.state != TASK_STATE_RUNNING:
			self.set_state(TASK_STATE_STOPPED)
			
	def defer(self):
		self._defer_signal = True
	
	def remove(self):
		self._pending_deletion_signal = True
		if self.state != TASK_STATE_RUNNING:
			self.set_state(TASK_STATE_PENDING_DELETION)
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
			task._calculate_next_run()
		for s in d['steps']:
			# I hate this
			step_module = eval(s['module'])
			task.add_step(step_module, s['function'], s['args'], s['kwargs'])
		return task
									
									
		