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
			r = self._db.table('profile').insert({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})
		return r
		
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
			r = self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, eids = [int(profile_id)])
		return r
	"""
	Delete a profile
	Also remove any background processor credentials associated with the profile
	"""
	def profileDeleteById(self, profile_id):
		r = False
		if self._db.table('profile').contains(eids = [int(profile_id)]):
			with self._lock:
				r = self._db.table('profile').remove(eids = [int(profile_id)])
			self.backgroundProcessorCredentialsUnset(profile_id)	
		return r
		
	def backgroundProcessorCredentialsSet(self, profile_id, hx_api_username, hx_api_password):
		with self._lock:
			r = self._db.table('background_processor_credential').insert({'profile_id' : int(profile_id), 'hx_api_username' : hx_api_username, 'hx_api_password' : hx_api_password})
		return r	
	
	def backgroundProcessorCredentialsUnset(self, profile_id):
		r = False
		e = self.backgroundProcessorCredentialsGet(profile_id)
		if e:
			with self._lock:
				r = self._db.table('background_processor_credential').remove(eids = [e.eid])	
		return r
		
	def backgroundProcessorCredentialsGet(self, profile_id):
		return self._db.table('background_processor_credential').get(tinydb.Query()['profile_id'] == int(profile_id))
		
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
			r = self._db.table('alert').update(alert, eids = [alert.eid])
		return r
		