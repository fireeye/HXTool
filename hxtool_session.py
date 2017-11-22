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
	def __init__(self, hxtool_db_instance, app_secret, logger):
		def on_update(self):
			# This a new session
			if not self.id:
				self.new_session()
				self.logger.debug("Creating a new session with id: {0}".format(self.id))
			self.sign()
			self._ht_db.sessionUpdate(self.id, self, self.signature)
			self.accessed = True
			self.modified = True
			
		self.logger = logger
		CallbackDict.__init__(self, on_update=on_update)
		self._ht_db = hxtool_db_instance
		self.nonce = None
		self.signature = None
		self.secret = app_secret
		self.id = None
		self.accessed = False
		self.modified = False
	
	def new_session(self):
		self.id = str(uuid.uuid4())
		self.nonce = self.generate_nonce()
		self._ht_db.sessionCreate(self.id, self.nonce)
	
	def get(self, cookie_value):
		self.id, self.signature = cookie_value.split('!', 1)
		session_record = self._ht_db.sessionGet(self.id)
		if session_record:
			self.nonce = session_record['session_nonce']
			if not session_record['session_signature'] == self.signature:
				self.logger.warn("Session signature verification failed.")
				return None
			self.update(session_record['session_data'])
			self.accessed = True
			return self
		return None

	def generate_nonce(self):
		return HXAPI.b64(os.urandom(32))
	
	def sign(self):
		self.signature = hxtool_session.hmac_sha256(HXAPI.b64(self.nonce, decode=True), self.secret, self.id)
		
	def verify(self, cookie_value):
		return (self.signature == cookie_parts[2])
		
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
		
	def open_session(self, app, request):
		cookie_value = request.cookies.get(app.session_cookie_name)
		if cookie_value:
			session = hxtool_session(self._ht_db, app.secret_key, self.logger).get(cookie_value)
			if session:
				self.logger.debug("We have an existing session with id: {0}".format(session.id))
				return session
			
		return hxtool_session(self._ht_db, app.secret_key, self.logger)
		
	def save_session(self, app, session, response):
		cookie_domain = self.get_cookie_domain(app)
		if not session:
			if session.id:
				self.logger.debug("Deleting session with id: {0}".format(session.id))
				self._ht_db.sessionDelete(session.id)
			if session.modified:
				response.delete_cookie(app.session_cookie_name, domain=cookie_domain)
			return
		
		if not self.should_set_cookie(app, session):
			return
		
		cookie_path = self.get_cookie_path(app)
		http_only = self.get_cookie_httponly(app)
		secure = self.get_cookie_secure(app)	
		response.set_cookie(app.session_cookie_name, session.get_cookie_value(), path=cookie_path, httponly=http_only, secure=secure, domain=cookie_domain)	
