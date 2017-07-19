from hxtool_db import *
import zipfile
import json	
import xml.etree.ElementTree as ET
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
	from StringIO import StringIO
except ImportError:
	# Running on Python 3.x
	from io import StringIO


def findPayloadServiceMD5(sourcefile):
	with zipfile.ZipFile(StringIO(sourcefile)) as zf:
		data = zf.read("manifest.json")
		arrData = json.loads(data)
		for audit in arrData['audits']:
			if audit['generator'] == "w32services":
				for item in audit['results']:
					if item['type'] == "application/xml":
						return item['payload']

def parsePayloadServiceMD5(sourcefile, payloadname):
	with zipfile.ZipFile(StringIO(sourcefile)) as zf:
		data = zf.read(payloadname)
		return data

def parseXmlServiceMD5Data(sourcedata):

	tree = ET.ElementTree(ET.fromstring(sourcedata))
	root = tree.getroot()

	acqdata = []

	for child in root:
		store = {}
		for data in child:
			store[data.tag] = data.text
		acqdata.append(store)
	
	return(acqdata)
		
def backgroundStackProcessor(c, conn, myConf, app):
	
	###
	### Control bulk acquisitions for stacking job
	##############################
	
	jobs = sqlGetStackJobs(c, conn)
	
	for job in jobs:
	
		stackid = job[0]
		jobtype = job[1]
		state = job[2]
		profileid = job[3]
		bulkid = job[4]
		hostset = job[5]
		c_rate = job[6]
		
		# If the job-profile doesn't have background credentials set - skip it
		if len(sqlGetProfCredTable(c, conn, profileid)) == 0:
			continue
		else:
			(hx_host, hx_port, hx_user, hx_pass) = sqlGetProfileBackgroundCredentials(c, conn, profileid)
			hx_api_object = HXAPI(hx_host, hx_port)
		
		(ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
		
		if ret:
			# User created a new stack job, create a new bulk acquisition
			if state == "SCHEDULED":
				
				app.logger.info("Stacking: Starting bulk acquisition - %s", jobtype)
							
				
				# Get the acquisition script
				if job[1] == "services-md5":
					bulkscript = open('scripts/services-md5.xml', 'r').read()
				
				# Post the new acquisition to the controller
				(ret, response_code, response_data) = hx_api_object.restNewBulkAcq(bulkscript, hostset)
				bulkid = response_data['data']['_id']
				
				out = sqlUpdateStackJobSubmitted(c, conn, stackid, bulkid)
				
				(ret, response_code, response_data) = hx_api_object.restLogout()
			
			# User requested the stack job to stop, stop it on the controller and change state
			if state == "STOPPING":
				
				app.logger.info("Stacking: Stopping bulk acquisition - %s", jobtype)
				
				(ret, response_code, response_data) = hx_api_object.restCancelJob('/hx/api/v2/acqs/bulk/', bulkid)
				out = sqlUpdateStackJobState(c, conn, stackid, "STOPPED")
				
				(ret, response_code, response_data) = hx_api_object.restLogout()
			
			# User requested the stack job to be removed, delete it on the controller and remove it from stacktable
			if state == "REMOVING":
			
				app.logger.info("Stacking: Removing bulk acquisition - %s", jobtype)

				(ret, response_code, response_data) = hx_api_object.restDeleteJob('/hx/api/v2/acqs/bulk/', bulkid)
				sqlDeleteStackServiceMD5(c, conn, stackid)
				sqlDeleteStackJob(c, conn, profileid, stackid)
				
				(ret, response_code, response_data) = hx_api_object.restLogout()
		
			# The bulk acquisition has been posted to the controller, poll it and check if its running and update the state
			if state == "SUBMITTED":
				
				(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(bulkid)
				
				if response_data['data']['state'] == "RUNNING":
					app.logger.info("Stacking: Bulk acquisition is running on the controller, update the state - %s", response_data['data']['state'])
					out = sqlUpdateStackJobState(c, conn, stackid, "RUNNING")

				(ret, response_code, response_data) = hx_api_object.restLogout()
		
			# The bulk acquisition is running on the controller, continously poll for new results and update the stats
			if state == "RUNNING":
			
				(ret, response_code, response_data) = hx_api_object.restGetBulkDetails(bulkid)
				
				# calculate completion rate
				total_size = response_data['data']['stats']['running_state']['NEW'] + response_data['data']['stats']['running_state']['QUEUED'] + response_data['data']['stats']['running_state']['FAILED'] + response_data['data']['stats']['running_state']['ABORTED'] + response_data['data']['stats']['running_state']['DELETED'] + response_data['data']['stats']['running_state']['REFRESH'] + response_data['data']['stats']['running_state']['CANCELLED'] + response_data['data']['stats']['running_state']['COMPLETE']
				if total_size == 0:
					completerate = 0
				else:
					completerate = int(float(response_data['data']['stats']['running_state']['COMPLETE']) / float(total_size) * 100)
				
				out = sqlUpdateStackJobProgress(c, conn, stackid, completerate)
				
				# query bulk acquisition results
				(ret, response_code, response_data) = hx_api_object.restListBulkDetails(bulkid)
				
				iter = 0
				for entry in response_data['data']['entries']:
					if entry['state'] == "COMPLETE":
						if not sqlQueryStackServiceMD5(c, conn, stackid, entry['host']['hostname']):
						
							app.logger.info("Stacking: Found completed bulk acquisition - %s", entry['host']['hostname'])
						
							(ret, response_code, response_data) = hx_api_object.restDownloadBulkAcq(entry['result']['url'])
						
							# Post-process acquisition results
							payload_data = findPayloadServiceMD5(response_data)
							payload_xml = parsePayloadServiceMD5(response_data, payload_data)
							payload_parsed = parseXmlServiceMD5Data(payload_xml)
						
							dbresult = sqlAddStackServiceMD5(c, conn, stackid, entry['host']['hostname'], payload_parsed)
							
							app.logger.info("Stacking: Completed post-processing - %s", entry['host']['hostname'])
							
							iter = iter + 1
					
					# If cap is reached break out and reloop
					if iter == myConf['background_processor']['stack_jobs_per_poll']:
						break
					
			(ret, response_code, response_data) = hx_api_object.restLogout()


from hx_lib import *
import threading			
import time
try:
	import Queue as queue
except ImportError:
	import queue

"""
Assume most systems are quad core, so 4 threads should be optimal - 1 thread per core
"""					
class hxtool_background_processor:
	def __init__(self, hxtool_config, hxtool_db, profile_id, thread_count = 4, logger = logging.getLogger(__name__)):
		self.logger = logger
		self._ht_db = hxtool_db
		# TODO: maybe replace with hx_hostname, hx_port variables in __init__
		profile = self._ht_db.profileGet(profile_id)
		self._hx_api_object = HXAPI(profile['hx_host'], profile['hx_port'])
		self.profile_id = profile_id
		self.thread_count = thread_count
		self._task_queue = queue.Queue()
		self._task_thread_list = []
		self._stop_event = threading.Event()
		self._poll_thread = threading.Thread(target = self.bulk_download_processor, name = "hxtool_background_processor", args = (hxtool_config['background_processor']['poll_interval'], ))
		# TODO: should be configurable
		self._download_directory_base = "bulkdownload"
		
	def __exit__(self, exc_type, exc_value, traceback):
		self.stop()
		
	def start(self, hx_api_username, hx_api_password):
		(ret, response_code, response_data) = self._hx_api_object.restLogin(hx_api_username, hx_api_password)
		if ret:
			self._poll_thread.start()
			for i in range(1, self.thread_count):
				task_thread = threading.Thread(target = self.await_task)
				self._task_thread_list.append(task_thread)
				task_thread.start()
		else:
			self.logger.error("Failed to login to the HX controller! Error: {0}".format(response_data))
			self.stop()
		
	def stop(self):
		self._stop_event.set()
		if self._poll_thread.is_alive():
			self._poll_thread.join()
		for task_thread in [t for t in self._task_thread_list if t.is_alive()]:
			task_thread.join()
		if self._hx_api_object.restIsSessionValid():
			(ret, response_code, response_data) = self._hx_api_object.restLogout()

	def bulk_download_processor(self, poll_interval):
		while not self._stop_event.is_set():
			bulk_jobs = self._ht_db.bulkDownloadList(self.profile_id)
			for job in [j for j in bulk_jobs if j['stopped'] == False]:
				download_directory = self.make_download_directory(job['bulk_download_id'])
				for host in [h for h in job['hosts'] if h['downloaded'] == False]:
					(ret, response_code, response_data) = self._hx_api_object.restGetBulkHost(job['bulk_download_id'], host['_id'])
					if ret:
						if response_data['data']['state'] == "COMPLETE" and response_data['data']['result']:
							full_path = os.path.join(download_directory, '{0}_{1}.zip'.format(host['host_name'], host['_id']))
							self._task_queue.put((self.download_task, (job['bulk_download_id'], host['_id'], job['stack_job'], response_data['data']['result']['url'], full_path)))
			time.sleep(poll_interval)
			
	def await_task(self):
		while not self._stop_event.is_set():
			task = self._task_queue.get()
			task[0](*task[1])
			self._task_queue.task_done()
			
	def download_task(self, bulk_download_id, host_id, is_stack_job, download_url, destination_path):
		(ret, response_code, response_data) = self._hx_api_object.restDownloadFile(download_url, destination_path)
		if ret:
			self._ht_db.bulkDownloadUpdateHost(self.profile_id, bulk_download_id, host_id)
			if is_stack_job:
				self._task_queue.put((self.stack_task, (bulk_download_id, destination_path,)))

	def stack_task(self, bulk_download_id, file_path):
		with zipfile.ZipFile(file_path) as f:
			acquisition_manifest = json.loads(f.read('manifest.json'))
			results_file = acquisition_manifest['audits'][0]['results'][0]['type']['payload']	
			results = f.read(results_files[0]['payload'])
			print(results)
			
	def make_download_directory(self, bulk_download_id):
		download_directory = os.path.join(self._download_directory_base, self._hx_api_object.hx_host, str(bulk_download_id))
		if not os.path.exists(download_directory):
			os.makedirs(download_directory)
		return download_directory