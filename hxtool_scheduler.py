#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import threading
import atexit
import datetime
import uuid

try:
	import Queue as queue
except ImportError:
	import queue

	
# Note: scheduler resolution is 1 second
class hxtool_scheduler:
	def __init__(self, task_status_callback = None, task_thread_count = 4, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._lock = threading.Lock()
		self.task_queue = []
		self.run_queue = queue.Queue()
		self._poll_thread = threading.Thread(target = self._scan_task_queue, name = "HXTool Task Scheduler")
		self.task_thread_count = task_thread_count
		self.task_threads = []
		self._stop_event = threading.Event()
		self.task_status_callback = task_status_callback
		atexit.register(self.stop)
		self.logger.info("Task scheduler initialized.")

	def _scan_task_queue(self):
		while not self._stop_event.is_set():
			for task in self.task_queue:
				if task.should_run():
					self.run_queue.put(task)
			self._stop_event.wait(1)
	
	def _await_task(self):
		while not self._stop_event.is_set():
			if not self.run_queue.empty():
				task = self.run_queue.get(True, 1)
				if task:
					self.logger.info("Executing task with id: %s, name: %s.", task.id, task.name)
					self._update_task_status(task.id, task.name, "Running")
					ret = task.run()
					status = "Completed"	
					if not ret:
						status = "Failed"
					self._update_task_status(task.id, task.name, status)
					self.run_queue.task_done()
		
	def _update_task_status(self, id, name, status):
		if self.task_status_callback:
			self.task_status_callback(id, name, status)
	
	def start(self):
		self._poll_thread.start()
		for i in range(1, self.task_thread_count):
			t = threading.Thread(target = self._await_task())
			t.start()
			self.task_threads.append(t)
		self.logger.info("Task scheduler started.")
		
	def stop(self):
		self._stop_event.set()
		self._poll_thread.join()
		for t in self.task_threads:
			if t.is_alive():
				t.join()
				
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
		
	def status(self):
		return True
			
# Interval must be zero or a time delta
# To run a job once at a specific time, specify start_time with an interval of zero
class hxtool_scheduler_task:
	def __init__(self, name, task_function, task_arguments, id = str(uuid.uuid4()), interval = 0, start_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=1), end_time = None, logger = logging.getLogger(__name__)):
		self._lock = threading.Lock()
		self.id = id
		self.name = name
		self.enabled = True
		self._interval = interval
		self.start_time = start_time
		self.end_time = end_time
		self.last_run = None
		self.next_run = self.start_time
		self.task_function = task_function
		self.task_arguments = task_arguments
			
	def _calculate_next_run(self):
		if not self._interval or self._interval == 0:
			with self._lock:
				self.next_run = None
			return
		
		if type(self._interval) is datetime.timedelta:
			with self._lock:
				self.next_run = (self.last_run + self._interval)
			return
	
	def run(self):
		with self._lock:
			self.last_run = datetime.datetime.utcnow()
		
		if self.task_arguments:
			ret = self.task_function(*self.task_arguments)
		else:
			ret = self.task_function()
			
		self._calculate_next_run()
		return ret
	
	def should_run(self):
		return self.enabled and (self.next_run - datetime.datetime.utcnow()).seconds == 1
		
		