#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import random
from time import sleep
import logging

sys.path.append('../')

from hxtool_scheduler import *

class test_scheduler:
	
	def __init__(self):
		self.ht_scheduler = hxtool_scheduler()
		self.ht_scheduler.logger.addHandler(logging.StreamHandler(sys.stdout))
		self.ht_scheduler.logger.setLevel(logging.DEBUG)
		
		
	def run_test(self):	
		print("Testing hxtool_scheduler...")
		self.ht_scheduler.start()
		for i in range(1, 500):
			ht_task = hxtool_scheduler_task('System', 'Test Task {}'.format(i), immutable = True, logger = self.ht_scheduler.logger)
			r = random.randint(1, 100)
			if r > 50:
				ht_task.set_schedule(minutes = random.randint(1, 5))
			ht_task.add_step(self, "test_scheduler_function", args = (random.randint(1, 60),))
			self.ht_scheduler.add(ht_task, should_store = False)
			ht_task = None

		try:	
			while True:
				sleep(.1)
		except (KeyboardInterrupt, SystemExit):
			self.ht_scheduler.stop()
			
	def test_scheduler_function(self, n):
		print("Random number is: {}".format(n * random.randint(0, 500)))
		return True
		
t = test_scheduler()
t.run_test()