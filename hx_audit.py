import xml.etree.ElementTree as ET
import zipfile
import json

def get_mime_type(generator):
	return (generator in ['w32apifile-acquisition', 'w32disk-acquisition']) and 'application/octet-stream' or 'application/xml'

def get_audit_records(audit_data, generator, item_name, fields=None, post_process=None, **static_values):
	items = []
	mime_type = get_mime_type(generator)
	if mime_type == 'application/xml':		
		xml_items = ET.fromstring(audit_data).findall('./{0}'.format(item_name))
		for xml_item in xml_items:
			item = dict(static_values)
			for e in xml_item:
				if fields and e.tag not in fields:
					continue
				# TODO: we only recurse 1 level deep - should recurse further
				if len(list(e)) > 0:
					item[e.tag] = [(_.tag, _.text) for _ in e[0]]
				else:
					item[e.tag] = e.text
						
			if post_process:
				item.update(post_process(audit_data))
				
			items.append(item)	
	elif mime_type == 'application/octet-stream' and post_process:
		item = dict(static_values)
		item.update(post_process(audit_data))
		items.append(item)
	else:
		#TODO: Unexpected mime_type?
		pass
	return items

class AuditPackage:
	def __init__(self, acquisition_package_path):
		self.package = zipfile.ZipFile(acquisition_package_path)
		self.manifest = ('manifest.json' in self.package.namelist()) and json.loads(self.package.read('manifest.json').decode('utf-8')) or {}
		self.audits = ('audits' in self.manifest) and self.manifest['audits'] or []

	# Ensure that we close the zip file so we don't leak file handles
	def __exit__(self, exc_type, exc_value, traceback):
		self.package.close()
		
	def get_generators(self):
		return [_['generator'] for _ in self.audits if 'generator' in _]

	def get_audit_id(self, generator):
		mime_type = get_mime_type(generator)
		for audit in self.audits:
			if audit['generator'] == generator and 'results' in audit:
				for results in audit['results']:
					if results['type'] == mime_type:
						return results['payload']
		return ''

	def get_audit(self, payload_name=None, generator=None, destination_path=None):
		if not payload_name and not generator:
			raise ValueError("You must specify payload_name or generator.")
		if payload_name and payload_name not in self.package.namelist():
			return None
		elif generator:
			payload_name = self.get_audit_id(generator)
			if payload_name == '':
				return None
				
		if destination_path:
			self.package.extract(payload_name, destination_path)
			return None
		
		return self.package.read(payload_name)
