#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import threading
import datetime
import uuid

try:
	import Queue as queue
except ImportError:
	import queue

TASK_STATE_IDLE = 0
TASK_STATE_QUEUED = 1
TASK_STATE_RUNNING = 2
TASK_STATE_COMPLETE = 3	

# Special task indicator that we need to exit now
SIGINT_TASK_ID = -1
	
# Note: scheduler resolution is a little less than a second
class hxtool_scheduler:
	def __init__(self, task_status_callback = None, task_thread_count = 4, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._lock = threading.Lock()
		self.task_queue = []
		self.run_queue = queue.Queue()
		self._poll_thread = threading.Thread(target = self._scan_task_queue, name = "HXTool Task Scheduler")
		self._stop_event = threading.Event()
		self.task_thread_count = task_thread_count
		self.task_threads = []
		self.task_status_callback = task_status_callback
		self.logger.info("Task scheduler initialized.")

	def _scan_task_queue(self):
		while not self._stop_event.is_set():
			for task in self.task_queue:
				if task.should_run():
					self.run_queue.put((task.id, task.name, task.run))
					task.set_state(TASK_STATE_QUEUED)
			self._stop_event.wait(.01)
		
	def _await_task(self):
		while not self._stop_event.is_set():
			(task_id, task_name, task_run) = self.run_queue.get()
			# Special task indicator that we need to exit now
			if task_id == SIGINT_TASK_ID:
				self.logger.debug("Got SIGINT_TASK_ID, exiting.")
				self.run_queue.task_done()
				break
			self.logger.info("Executing task with id: %s, name: %s.", task_id, task_name)
			self._update_task_status(task_id, task_name, "Running")
			ret = task_run()
			status = "Completed"
			if not ret:
				status = "Failed"
			self._update_task_status(task_name, task_id, status)
			self.run_queue.task_done()
					
	def _update_task_status(self, id, name, status):
		if self.task_status_callback:
			self.task_status_callback(id, name, status)
	
	def start(self):
		self._poll_thread.start()
		for i in range(0, self.task_thread_count):
			t = threading.Thread(target = self._await_task)
			t.start()
			self.task_threads.append(t)
		self.logger.info("Task scheduler started.")
		
	def stop(self):
		self._stop_event.set()
		if self._poll_thread.is_alive():
			self._poll_thread.join()
		for i in range(0, self.task_thread_count):
			self.run_queue.put((SIGINT_TASK_ID, None, None))
		for t in self.task_threads:
			if t.is_alive():
				t.join()
		self.run_queue.join()
	
	def add(self, task):
		with self._lock:
			self.task_queue.append(task)
		
	def remove(self, id = None, name = None):
		if id:
			t = [_ for _ in self.task_queue if _.id == id]
			with self.lock:
				self.task_queue.remove(t[0])
		elif name:
			t = [_ for _ in self.task_queue if _.name == name]
			with self.lock:
				self.task_queue.remove(t[0])		
	
	# Note get() is destructive, it will remove the task from the queue, you will need to add it back when done if you want to run it again.
	def get(self, id = None, name = None):
		if id:
			t = [_ for _ in self.task_queue if _.id == id]
			with self.lock:
				return self.task_queue.pop(self.task_queue.index(t[0]))
		elif name:
			t = [_ for _ in self.task_queue if _.name == name]
			with self.lock:
				return self.task_queue.pop(self.task_queue.index(t[0]))
				
	def tasks(self):
		return [_.__dict__ for _ in self.task_queue]
		
	def status(self):
		return self._poll_thread.is_alive()
			
# Interval must be zero or a time delta
# To run a job once at a specific time, specify start_time with an interval of zero
# States:
class hxtool_scheduler_task:
	def __init__(self, profile_id, name, id = str(uuid.uuid4()), interval = 0, start_time = datetime.datetime.utcnow(), end_time = None, enabled = True, immutable = False, stop_on_fail = True, parent_id = None, logger = logging.getLogger(__name__)):
		self._lock = threading.Lock()
		self.profile_id = profile_id
		self.id = id
		self.parent_id = parent_id
		self.name = name
		self.enabled = enabled
		self.immutable = immutable
		self.state = 0
		self.interval = interval
		self.start_time = start_time
		self.end_time = end_time
		self.last_run = None
		self.next_run = start_time
		self.stop_on_fail = stop_on_fail
		self.steps = []
		

	def add_step(self, function, args):
		with self._lock:
			self.steps.append((function, args))
		
	def _calculate_next_run(self):
		if not self.interval or self.interval == 0:
			self.next_run = None
		elif type(self.interval) is datetime.timedelta:
			self.next_run = (self.last_run + self.interval)
	
	# Use this to set state, its thread-safe
	def set_state(self, state):
		with self._lock:
			self.state = state
			
	def run(self):
		with self._lock:
			self.state = TASK_STATE_RUNNING
			
			# Reset microseconds to keep from drifting too badly
			self.last_run = datetime.datetime.utcnow().replace(microsecond=1)
			
			for func, args in self.steps:
				if args:
					ret = func(*args)
				else:
					ret = func()
				
				if not ret and self.stop_on_fail:
					break
			
			self._calculate_next_run()
			
			if self.next_run:
				self.state = TASK_STATE_IDLE
			else:
				self.state = TASK_STATE_COMPLETE
				
		return ret
	
	def should_run(self):
		return (self.enabled and  
				self.state == TASK_STATE_IDLE and 
				len(self.steps) > 0 and 
				((datetime.datetime.utcnow() - self.next_run).seconds == 0 or 
				self.start_time == self.next_run))
		