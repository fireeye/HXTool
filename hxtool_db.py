import tinydb
import tinydb.operations
import threading
import datetime

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
	Delete a profile by id
	"""
	def profileGetById(self, profile_id):
		profile = self._db.table('profile').get(eid = int(profile_id))
		if profile:
			profile['profile_id'] = profile.eid
			return profile
		else:
			return None
			
	def profileUpdateById(self, profile_id, hx_name, hx_host, hx_port):
		with self._lock:
			return self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, eids = [int(profile_id)])
		
	"""
	Delete a profile
	Also remove any background processor credentials associated with the profile
	"""
	def profileDeleteById(self, profile_id):
		self.backgroundProcessorCredentialsUnset(profile_id)	
		with self._lock:
			return self._db.table('profile').remove(eids = [int(profile_id)])
		
	def backgroundProcessorCredentialsSet(self, profile_id, hx_api_username, hx_api_password, salt):
		with self._lock:
			r = self._db.table('background_processor_credential').insert({'profile_id' : int(profile_id), 'hx_api_username' : hx_api_username, 'hx_api_password' : hx_api_password, 'salt': salt})
		return r	
	
	def backgroundProcessorCredentialsUnset(self, profile_id):
		with self._lock:
			return self._db.table('background_processor_credential').remove((tinydb.Query()['profile_id'] == int(profile_id)))
			
	def backgroundProcessorCredentialsGet(self, profile_id):
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
		alert['annotations'].append({'annotation' : annotation, 'state' : int(state), 'create_user' : create_user, 'create_timestamp' : str(datetime.datetime.utcnow())})
		with self._lock:
			return self._db.table('alert').update(alert, eids = [alert.eid])
		
	def bulkDownloadAdd(self, profile_id, bulk_download_id, host_count):
		with self._lock:
			return self._db.table('bulk_download').insert({'profile_id' : int(profile_id), 'bulk_download_id': int(bulk_download_id), 'host_count' : int(host_count), 'hosts_complete' : 0, 'stopped' : False})
	
	def bulkDownloadGet(self, profile_id, bulk_download_id):
		return self._db.table('bulk_download').get((tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadList(self, profile_id):
		return self._db.table('bulk_download').all()
	
	def bulkDownloadUpdate(self, profile_id, bulk_download_id, host_count = None, hosts_complete = None):
		fields = {}
		if host_count:
			fields['host_count'] = host_count
		if hosts_complete:
			fields['hosts_complete'] = hosts_complete
			
		with self._lock:
			return self._db.table('bulk_download').update(fields, (tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
		
	def bulkDownloadStop(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').update({'stopped' : True}, (tinydb.Query()['profile_id'] == int(profile_id)) & (tinydb.Query()['bulk_download_id'] == int(bulk_download_id)))
	
	def bulkDownloadDelete(self, profile_id, bulk_download_id):
		with self._lock:
			return self._db.table('bulk_download').remove((tinydb.Query()['profile_id'] == int(profile_id)) & 
														(tinydb.Query()['bulk_download_id'] == int(bulk_download_id)) & 
														(tinydb.Query()['stopped'] == True))
		