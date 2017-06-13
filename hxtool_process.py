from hxtool_db import *
import zipfile
import json
from StringIO import StringIO
import xml.etree.ElementTree as ET
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
					if iter == myConf['backgroundProcessor']['stack_jobs_per_poll']:
						break
					
			(ret, response_code, response_data) = hx_api_object.restLogout()

def backgroundBulkProcessor(c, conn, myConf, app):

	### Function to check and download bulk acquisitions
	####################################
	
	bulkjobs = sqlGetBulkDownloads(c, conn)
	
	for bulkjob in bulkjobs:
	
		profileid = bulkjob[0]
		bulkid =  bulkjob[1]
		hosts  = bulkjob[2]
		hostscomplete = bulkjob[3]
		hxtotal_agents = "100000"
		
		if len(sqlGetProfCredTable(c, conn, profileid)) == 0:
			continue
		
		(hx_host, hx_port, hx_user, hx_pass) = sqlGetProfileBackgroundCredentials(c, conn, profileid)
		
		hx_api_object = HXAPI(hx_host, hx_port)
		
		(ret, response_code, response_data) = hx_api_object.restLogin(hx_user, hx_pass)
		
		if ret:
			json_request_headers = {'X-FeApi-Token': hx_api_object.get_token['token'], 'Accept': 'application/json'}
			zip_request_headers = {'X-FeApi-Token': hx_api_object.get_token['token'], 'Accept': 'application/octet-stream'}
			
			bulk_url = 'https://{:s}:{:s}{:s}{:s}{:s}{:s}'.format(hx_host, hx_port, "/hx/api/v2/acqs/bulk/", str(bulkid), '/hosts?limit=', hxtotal_agents)

			r = requests.get(bulk_url, headers = json_request_headers, stream = True, verify = False)

			if r.status_code != 200:
				print('Couldn\'t download {:s}. Status code was {:d}'.format(bulk_url, r.status_code))

			rjson = json.loads(r.text)

			if hosts == 0:
				hc = sqlUpdateBulkDownloadHosts(c, conn, len(rjson['data']['entries']), profileid, bulkid)
			
			hiter = 0
			for host in rjson['data']['entries']:

				if host['result'] == None:
					continue

				directory = "bulkdownload/" + str(hxname) + "_" + str(bulkid)

				if not os.path.exists(directory + "/" + host['host']['hostname'] + "_" + host['host']['_id'] +  ".zip"):

					hiter = hiter + 1
					
					# download the zip
					get_dataurl = 'https://{:s}:{:s}{:s}'.format(hxip, hxport, host['url']) + ".zip"
					rd = requests.get(get_dataurl, headers = zip_request_headers, stream = True, verify = False)

					# write data to disk
					if not os.path.exists(directory):
						os.makedirs(directory)
						
					fulloutputpath = os.path.join(directory + "/" + host['host']['hostname'] + "_" + host['host']['_id'] +  ".zip")

					app.logger.info("Bulk Downloader: Writing file - " + directory + "/" + host['host']['hostname'] + "_" + host['host']['_id'] +  ".zip")
					with open(fulloutputpath, 'wb') as f:
						for chunk in rd.iter_content(1024):
							f.write(chunk)
							
					hd = sqlUpdateBulkDownloadHostsComplete(c, conn, profileid, bulkid)
					
				# If cap is reached break out and reloop
				if hiter == myConf['backgroundProcessor']['downloads_per_poll']:
					break
					
			(ret, response_code, response_data) = hx_api_object.restLogout()
			
		
		
		
		