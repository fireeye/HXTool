import threading
import datetime

try:
	import tinydb
	import tinydb.operations
except ImportError:
	print("hxtool_db requires the TinyDB module, please install it.")
	exit(1)

from hx_lib import *

class hxtool_db:
	def __init__(self, db_file):
		self._db = tinydb.TinyDB(db_file)
		self._lock = threading.RLock()
		
	def __exit__(self, exc_type, exc_value, traceback):
		if self._db:
			self._db.close()
	"""
	Add a profile
	Dictionary structure is:
	{
		'hx_name' : 'profile name to be displayed when referencing this profile',
		'hx_host' : 'the fully qualified domain name or IP address of the HX controller',
		'hx_port' : the integer port to use when communicating with the aforementioned HX controller
	}
	"""	
	def profileCreate(self, hx_name, hx_host, hx_port):
		with self._lock:
			return self._db.table('profile').insert({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})
		
	"""
	List all profiles
	"""
	def profileList(self):
		profiles = self._db.table('profile').all()
		for p in profiles: p['profile_id'] = p.eid
		return profiles
	
	"""
	Get a profile by id
	"""
	def profileGet(self, profile_id):
		profile = self._db.table('profile').get(eid = int(profile_id))
		if profile:
			profile['profile_id'] = profile.eid
			return profile
		else:
			return None
			
	def profileUpdate(self, profile_id, hx_name, hx_host, hx_port):
		with self._lock:
			return self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, eids = [int(profile_id)])
		
	"""
	Delete a profile
	Also remove any background processor credentials associated with the profile
	"""
	def profileDelete(self, profile_id):
		self.backgroundProcessorCredentialRemove(profile_id)	
		with self._lock:
			return self._db.table('profile').remove(eids = [int(profile_id)])
		
	def backgroundProcessorCredentialCreate(self, profile_id, hx_api_username, iv, salt, hx_api_encrypted_password):
		with self._lock:
			return self._db.table('background_processor_credential').insert({'profile_id' : int(profile_id), 'hx_api_username' : hx_api_username, 'iv' : iv, 'salt': salt, 'hx_api_encrypted_password' : hx_api_encrypted_password})
	
	def backgroundProcessorCredentialRemove(self, profile_id):
		with self._lock:
			return self._db.table('background_processor_credential').remove((tinydb.Query()['profile_id'] == int(profile_id)))
			
	def backgroundProcessorCredentialGet(self, profile_id):
		return self._db.table('background_processor_credential').get((tinydb.Query()['profile_id'] == int(profile_id)))
		
	def alertCreate(self, profile_id, hx_alert_id):
		r = self.alertGet(profile_id, hx_alert_id)
		if not r:
			with self._lock:
				r = self._db.table('alert').insert({'profile_id' : int(profile_id), 'hx_alert_id' : int(hx_alert_id), 'annotations' : []})
		else:
			r = r.eid
		return r
	
	def alertGet(self, profile_id, hx_alert_id):
		return self._db.table('alert').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['hx_alert_id'] == int(hx_alert_id)))
	
	def alertAddAnnotation(self, profile_id, hx_alert_id, annotation, state, create_user):
		alert = self.alertGet(profile_id, hx_alert_id)
		with self._lock:
			alert['annotations'].append({'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : str(datetime.datetime.utcnow())})		
			return self._db.table('alert').update(alert, eids = [alert.eid])
		
	def bulkDownloadCreate(self, profile_id, bulk_download_id, hosts, hostset_id = -1, stack_job = False):
		with self._lock:
			return self._db.table('bulk_download').insert({'profile_id' : int(profile_id), 'bulk_download_id': int(bulk_download_id), 'hosts' : hosts, 'hostset_id' : hostset_id, 'stopped' : False, 'stack_job' : stack_job})
	
	def bulkDownloadGet(self, profile_id, bulk_download_id):
		return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadList(self, profile_id):
		return self._db.table('bulk_download').search((tinydb.Query()['profile_id'] == int(profile_id)))
	
	def bulkDownloadUpdateHost(self, profile_id, bulk_download_id, host_id):
		r = self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == int(profile_id)) & 
												(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
		if r and r['hosts'].index({'_id' : host_id}):
			with self._lock:
				r['hosts'][r['hosts'].index({'_id' : host_id})]['downloaded'] = True
				return self._db.table('bulk_download').update(r, eids = [ r.eid ])
																			
	def bulkDownloadStop(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').update({'stopped' : True}, (tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').remove((tinydb.Query()['profile_id'] == int(profile_id)) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) & 
														(tinydb.Query()['stopped'] == True))
														
	def stackJobCreate(self, profile_id, bulk_download_id, hostset_id = -1):
		with self._lock:
			return self._db.table('stacking').insert({'profile_id' : int(profile_id), 'bulk_download_id' : int(bulk_download_id), 'hostset_id' : int(hostset_id), 'create_timestamp' : str(datetime.datetime.utcnow()), 'update_timestamp' : str(datetime.datetime.utcnow()), 'hosts' : []})
	
	def stackJobGet(self, profile_id, bulk_download_id):
		return self._db.table('stacking').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def stackJobList(self, profile_id):
		return self._db.table('stacking').search((tinydb.Query()['profile_id'] == int(profile_id)))
	
	def stackJobAddHost(self, profile_id, bulk_download_id, host_id, results):
		r = self.stackGet(profile_id, bulk_download_id)
		if r:
			h = { '_id' : host_id, 'results' : results, 'processed' : True}
			with self._lock:
				r['hosts'].append(h)
				r['update_timestamp'] = str(datetime.datetime.utcnow())
				return self._db.table('stacking').update(r, eids = [r.eid])
	
	def stackJobDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.remove((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))