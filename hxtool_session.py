#!/usr/bin/env python
# -*- coding: utf-8 -*-

from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin
import uuid
import os
import hmac
import hashlib
from hx_lib import *

class hxtool_session(CallbackDict, SessionMixin):
	def __init__(self, app_secret, logger):
		def on_update(self):	
			if self.accessed == False:
				self.modified = True
			
		self.logger = logger
		self.secret = app_secret
		self.id = None
		self.nonce = None
		self.signature = None
		self.new = True
		self.accessed = False
		self.modified = False
		CallbackDict.__init__(self, on_update=on_update)
		
	def create(self):
		self.id = str(uuid.uuid4())
		self.nonce = self.generate_nonce()		
		
	def load(self, id, signature, session_record):	
		if session_record:
			self.logger.debug("Loading saved session data.")
			# Set accessed to True for set/update so we don't loop into on_update()
			self.accessed = True
			# Explicitly set modified to False
			self.modified = False
			self.id = id
			self.nonce = session_record['session_nonce']
			self.signature = signature
#			if not session_record['session_signature'] == self.signature:
#				self.logger.warn("Session signature verification failed.")
#				session.clear()
#				return
			self.update(session_record['session_data'])
			self.accessed = False
		
	def generate_nonce(self):
		return HXAPI.b64(os.urandom(32))
	
	def sign(self):
		self.signature = hxtool_session.hmac_sha256(HXAPI.b64(self.nonce, decode=True), self.secret, self.id)
		
	def get_cookie_value(self):
		return "{0}!{1}".format(self.id, self.signature)
	
	@staticmethod
	def hmac_sha256(nonce, secret, data):
		s = nonce + secret.encode('utf-8')
		data = data.encode('utf-8')
		return HXAPI.b64(hmac.new(s, data, digestmod=hashlib.sha256).digest())
		
class hxtool_session_interface(SessionInterface):
	def __init__(self, hxtool_db_instance, logger):
		self._ht_db = hxtool_db_instance
		self.logger = logger
		self.session_cache = {}
		
	def open_session(self, app, request):
		session = hxtool_session(app.secret_key, self.logger)
		
		cookie_value = request.cookies.get(app.session_cookie_name)
		if cookie_value:
			id, signature = cookie_value.split('!', 1)
			if id and signature:
				cached_session = self.session_cache.get(id)
				if not cached_session:					
					session_record = self._ht_db.sessionGet(id)
					if session_record:
							session.load(id, signature, session_record)
							self.logger.debug("We have an existing database session with id: {0}".format(session.id))
				else:
					session = cached_session
					self.logger.debug("We have an existing cached session with id: {0}".format(session.id))
	
		
		return session
		
	def save_session(self, app, session, response):
		cookie_domain = self.get_cookie_domain(app)
		if not session:
			if not session.new:
				self.logger.debug("Deleting session with id: {0}".format(session.id))
				self._ht_db.sessionDelete(session.id)
				if id in self.session_cache:
					del self.session_cache[session.id]
			if session.modified:
				response.delete_cookie(app.session_cookie_name, domain=cookie_domain)
			return
		
		if not self.should_set_cookie(app, session):
			return
		
		if session.new:
			session.create()
			self._ht_db.sessionCreate(session.id, session.nonce)
			self.logger.debug("Created a new session with id: {0}".format(session.id))
			session.new = False
			
		self.logger.debug("Saving session with id: {0}".format(session.id))
		self._ht_db.sessionUpdate(session.id, session, session.signature)
		session.modified = False
		
		self.session_cache[session.id] = session
		
		cookie_path = self.get_cookie_path(app)
		http_only = self.get_cookie_httponly(app)
		secure = self.get_cookie_secure(app)	
		response.set_cookie(app.session_cookie_name, session.get_cookie_value(), path=cookie_path, httponly=http_only, secure=secure, domain=cookie_domain)	
