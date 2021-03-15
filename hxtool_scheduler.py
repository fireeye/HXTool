#!/usr/bin/env python
# -*- coding: utf-8 -*-

logger = hxtool_logging.getLogger(__name__)

try:
	import keyring
except ImportError:
	logger.error("The HXTool scheduler requires the keyring module in order to securely store credentials needed to interact with the controller. Please install it.")
	exit(1)

import threading
import datetime
from argparse import Namespace
from multiprocessing.pool import ThreadPool
from multiprocessing import cpu_count, TimeoutError

import hxtool_logging
import hxtool_global
from hx_lib import HXAPI
from hxtool_util import pretty_exceptions, crypt_pbkdf2_hmacsha256, crypt_aes
from hxtool_vars import default_encoding
# TODO: Move background API session initialization out of scheduler
from hxtool_scheduler_task import hxtool_scheduler_task, task_states
from hxtool_task_modules import task_api_session_module

MAX_HISTORY_QUEUE_LENGTH = 1000

TASK_API_KEY = 'Z\\U+z$B*?AiV^Fr~agyEXL@R[vSTJ%N&'.encode(default_encoding)

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
		task.set_state(task_states.TASK_STATE_QUEUED)
		logger.debug("Executing task with id: %s, name: %s.", task.task_id, task.name)
		try:
			ret = task.run(self)
		except Exception as e:
			logger.error(pretty_exceptions(e))
			task.set_state(task_states.TASK_STATE_FAILED)
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
		api_login_task.add_step(task_api_session_module, kwargs = {
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
				decrypted_background_password = keyring.get_password("hxtool_{}".format(profile['profile_id']), task_api_credential['hx_api_username'])
				# TODO: eventually remove this code once most people are using keyring
				if not decrypted_background_password:
					logger.info("Background credential for {} is not using keyring, moving it.".format(profile['profile_id']))
					try:
						salt = HXAPI.b64(task_api_credential['salt'], True)
						iv = HXAPI.b64(task_api_credential['iv'], True)
						key = crypt_pbkdf2_hmacsha256(salt, TASK_API_KEY)
						decrypted_background_password = crypt_aes(key, iv, task_api_credential['hx_api_encrypted_password'], decrypt = True)
						keyring.set_password("hxtool_{}".format(profile['profile_id']), task_api_credential['hx_api_username'], decrypted_background_password)
						hxtool_db.backgroundProcessorCredentialRemove(profile['profile_id'])
						hxtool_db.backgroundProcessorCredentialCreate(profile['profile_id'], task_api_credential['hx_api_username'])
					except (UnicodeDecodeError, ValueError):
						logger.error("Please reset the background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
				
				if decrypted_background_password:
					self._add_task_api_task(profile['profile_id'], profile['hx_host'], profile['hx_port'], task_api_credential['hx_api_username'], decrypted_background_password) 
					decrypted_background_password = None
			else:
				logger.info("No background credential for {} ({}).".format(profile['hx_host'], profile['profile_id']))
	
	def add_task_api_session(self, profile_id, hx_host, hx_port, username, password):
		keyring.set_password("hxtool_{}".format(profile_id), username, password)
		hxtool_global.hxtool_db.backgroundProcessorCredentialCreate(profile_id, username)
		self._add_task_api_task(profile_id, hx_host, hx_port, username, password)
		password = None
	
	def remove_task_api_session(self, profile_id):
		task_api_credential = hxtool_global.hxtool_db.backgroundProcessorCredentialGet(profile_id)
		try:
			keyring.delete_password("hxtool_{}".format(profile_id), task_api_credential['hx_api_username'])
		except keyring.errors.PasswordDeleteError as e:
			logger.error("Failed to remove keyring credential for {}, error {}".format(profile_id, e))			
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
			task.set_state(task_states.TASK_STATE_SCHEDULED)
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
		
