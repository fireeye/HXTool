import tinydb
import tinydb.operations
import threading
from hx_lib import *

class hxtool_db:
	def __init__(self, db_file):
		self._db = tinydb.TinyDB(db_file)
		self._lock = threading.RLock()
		
	def __exit__(self, exc_type, exc_value, traceback):
		if self._db:
			self._db.close()
						
	def profileCreate(self, hx_name, hx_host, hx_port):
		with self._lock:
			r = self._db.table('profile').insert({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port})
		return r
		
	def profileList(self):
		profiles = self._db.table('profile').all()
		for p in profiles: p['_id'] = p.eid
		return profiles
		
	def profileGetById(self, profile_id):
		profile = self._db.table('profile').get(eid = int(profile_id))
		if profile:
			profile['_id'] = profile.eid
			return profile
		else:
			return None
			
	def profileUpdateById(self, profile_id, hx_name, hx_host, hx_port):
		with self._lock:
			r = self._db.table('profile').update({'hx_name' : hx_name, 'hx_host' : hx_host, 'hx_port' : hx_port}, eids = [int(profile_id)])
		return r
		
	def profileDeleteById(self, profile_id):
		r = False
		if self._db.table('profile').contains(eids = [int(profile_id)]):
			with self._lock:
				r = self._db.table('profile').remove(eids = [int(profile_id)])
		return r
		
	def backgroundProcessorCredentialsSet(self, profile_id, hx_api_username, hx_api_password):
		with self._lock:
			r = self._db.table('background_processor_credentials').insert({'profile_id' : int(profile_id), 'hx_api_username' : hx_api_username, 'hx_api_password' : hx_api_password})
		return r	
	
	def backgroundProcessorCredentialsUnset(self, profile_id):
		r = False
		e = self._db.table('background_processor_credentials').get(tinydb.Query()['profile_id'] == int(profile_id))
		if e:
			with self._lock:
				r = self._db.table('background_processor_credentials').remove(eids = [e.eid])	
		return r
		
	def backgroundProcessorCredentialsExist(self, profile_id):
		return self._db.table('background_processor_credentials').contains(tinydb.Query()['profile_id'] == int(profile_id))