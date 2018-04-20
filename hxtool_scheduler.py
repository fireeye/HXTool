#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import threading
import datetime
import uuid
import random

try:
	import Queue as queue
except ImportError:
	import queue

import hxtool_global	


TASK_STATE_QUEUED = 0
TASK_STATE_RUNNING = 1
TASK_STATE_COMPLETE = 2
TASK_STATE_STOPPED = 3
TASK_STATE_FAILED = 4

task_state_description = {
	TASK_STATE_QUEUED 	: "Queued",
	TASK_STATE_RUNNING	: "Running",
	TASK_STATE_COMPLETE : "Complete",
	TASK_STATE_STOPPED	: "Stopped",
	TASK_STATE_FAILED	: "Failed"
}


# Special task indicator that we need to exit now
SIGINT_TASK_ID = -1
		
# Note: scheduler resolution is a little less than a second
class hxtool_scheduler:
	def __init__(self, task_thread_count = 4, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._lock = threading.Lock()
		self.task_queue = []
		self.run_queue = queue.Queue()
		self._poll_thread = threading.Thread(target = self._scan_task_queue, name = "PollThread")
		self._stop_event = threading.Event()
		self.task_thread_count = task_thread_count
		self.task_threads = []
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
			ret = task_run()
			self.run_queue.task_done()
						
	def start(self):
		self._poll_thread.start()
		for i in range(0, self.task_thread_count):
			t = threading.Thread(target = self._await_task, name = "TaskThread - {}".format(i))
			t.start()
			self.task_threads.append(t)
		self.logger.info("Task scheduler started.")
		
	def stop(self):
		self.logger.debug('stop() enter.')		
		for i in range(0, len(self.task_threads)):
			self.run_queue.put((SIGINT_TASK_ID, None, None))
		self.run_queue.join()
		self._stop_event.set()
		del self.task_threads[:]
		self.logger.debug('stop() exit.')
	
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
	def __init__(self, profile_id, name, id = str(uuid.uuid4()), interval = 0, start_time = datetime.datetime.utcnow(), end_time = None, enabled = True, immutable = False, stop_on_fail = True, parent_id = None, defer_interval = 30, logger = logging.getLogger(__name__)):
		self.logger = hxtool_global.hxtool_scheduler.logger
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
		self.run_state = None
		self.next_run = start_time
		self.stop_on_fail = stop_on_fail
		self.steps = []
		self.stored_result = None
		self.defer_interval = defer_interval
		
		self._stop_signal = False
		self._defer_signal = False
		

	def add_step(self, func, args = (), kwargs = {}):
		with self._lock:
			self.steps.append((func, args, kwargs))
		
	def _calculate_next_run(self):
		self.next_run = None
		if type(self.interval) is datetime.timedelta:
			self.next_run = (self.last_run + self.interval)
		elif self._defer_signal:
			# Add some random seconds to the interval to keep the task threads from deadlocking
			self.next_run = (self.last_run + datetime.timedelta(seconds = (self.defer_interval + random.randint(1, 15))))
	
	# Use this to set state, its thread-safe
	def set_state(self, state):
		with self._lock:
			self.state = state
	
	def run(self):
		self._stop_signal = False
		self._defer_signal = False
		ret = False
		
		if self.enabled:
			
			with self._lock:
				ret = False
				
				self.state = TASK_STATE_RUNNING
				
				# Reset microseconds to keep from drifting too badly
				self.last_run = datetime.datetime.utcnow().replace(microsecond=1)
				
				for func, args, kwargs in self.steps:
					# This is an HXTool task_module - need to find a better way to do this.
					if 'task_module' in func.__str__():
						if self.stored_result:
							kwargs.update(self.stored_result)
						(ret, result) = func(*args, **kwargs)
						self.stored_result = result
					else:
						ret = func(*args, **kwargs)
					
					if self._stop_signal:
						self.state = TASK_STATE_STOPPED
						break
					elif self._defer_signal:
						break
					elif not ret and self.stop_on_fail:
						self.state = TASK_STATE_FAILED
						break
			
				self._calculate_next_run()
			
				if self.next_run:
					self.state = TASK_STATE_QUEUED
				elif not (self.state == TASK_STATE_FAILED or self.state == TASK_STATE_STOPPED):
					self.state = TASK_STATE_COMPLETE
										
		else:
			self.set_state(TASK_STATE_STOPPED)
			
		return ret

	def stop(self):
		self._stop_signal = True
	
	def defer(self):
		self._defer_signal = True
	
	def should_run(self):
		return (self.enabled and  
				self.state == TASK_STATE_QUEUED and 
				len(self.steps) > 0 and 
				((datetime.datetime.utcnow() - self.next_run).seconds == 0 or 
				self.start_time == self.next_run))
		