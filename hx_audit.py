import xml.etree.ElementTree as ET
import zipfile
import json
from collections import OrderedDict

def get_mime_type(generator):
	return (generator in ['w32apifile-acquisition', 'w32disk-acquisition']) and 'application/octet-stream' or 'application/xml'

# TODO: replace code that uses this with AuditPackage.audit_to_dict	
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
		self.metadata = ('metadata.json' in self.package.namelist()) and json.loads(self.package.read('metadata.json').decode('utf-8')) or None
		
		self.hostname = None
		self.agent_id = None
		
		self._set_metadata()
	
	def _set_metadata(self):
		if self.metadata:
			self.hostname = self.metadata['agent']['sysinfo']['hostname']
			self.agent_id = self.metadata['agent']['_id']
		else:
			sysinfo_audit = self.get_generator_result('sysinfo')
			if sysinfo_audit:
				sysinfo_result = self.get_audit(payload_name = sysinfo_audit['payload'])
				if sysinfo_audit['type'] == 'application/xml':
					self.hostname = ET.fromstring(sysinfo_result).find('.//hostname').text
				elif sysinfo_audit['type'] == 'application/json':
					self.hostname = json.loads(sysinfo_result)['SystemInfoItem'][0]['hostname']
					
	def __enter__(self):
		return self
		
	# Ensure that we close the zip file so we don't leak file handles
	def __exit__(self, exc_type, exc_value, traceback):
		self.package.close()
	
	def parsable_mime_type(self, mime_type):
		return mime_type in ['application/xml', 'application/json']
	
	def get_generator_result(self, generator):
		for audit in self.audits:
			if audit['generator'] == generator and 'results' in audit:
				for result in audit['results']:
					if self.parsable_mime_type(result['type']):
						return result
		return None

	def get_audit(self, payload_name=None, generator=None, destination_path=None, open_only=False):
		if not payload_name and not generator:
			raise ValueError("You must specify payload_name or generator.")
		if payload_name and payload_name not in self.package.namelist():
			return None
		elif generator:
			payload_name = self.get_generator_result(generator)['payload']
			if not payload_name:
				return None
			
		if destination_path:
			self.package.extract(payload_name, destination_path)
			return None
			
		if open_only:
			return self.package.open(payload_name)
		
		return self.package.read(payload_name).decode('utf-8')	
		
	def audit_to_dict(self, audit, hostname, agent_id = None, batch_mode = True):
		d = {
				'hostname' : self.hostname or hostname,
				'agent_id' : self.agent_id or agent_id,
				'generator' : audit['generator'],
				'generatorVersion' : audit['generatorVersion']
			}
		
		for result in audit['results']:
			if self.parsable_mime_type(result['type']):
				d['timestamps'] = result['timestamps']
				
				payload = self.get_audit(payload_name = result['payload'], open_only = True)
				
				if payload:
					if result['type'] == 'application/xml':							
						payload_item_tag = None
						batch_dict = {'results' : []}
						xml_iterator = ET.iterparse(payload, events = ["start", "end"])
						
						(event, elem) = xml_iterator.next()	
						if elem.tag == "itemList" and event == "start":
							if len(elem) == 0:
								# Empty payload
								return
							
							# Find the payload item element tag
							(event, elem) = xml_iterator.next()
							payload_item_tag = elem.tag
							
							for event, elem in xml_iterator:							
								if elem.tag == payload_item_tag and event == "end":
									result_dict = self.xml_to_dict(elem)
							
									# Free memory used by the elements
									elem.clear()
									
									if batch_mode:
										batch_dict['results'].append(result_dict)
									else:
										result_dict.update(d)
										yield result_dict									
										# Free memory used by the result dictionary
										result_dict.clear()
							
							if batch_mode:
								batch_dict.update(d)
								yield batch_dict
								batch_dict.clear()
							
					elif result['type'] == 'application/json':
						audit_json = json.load(payload)
						payload = None
						
						audit_item = None
						for e in audit_json:
							if not e.startswith("@"):
								audit_item = e
								break
								
						if batch_mode:
							result_dict = {
								'results' : [{audit_item : _} for _ in audit_json[audit_item]]
							}
							result_dict.update(d)
							yield result_dict
							result_dict.clear()
						else:
							for itm in audit_json[audit_item]:
								result_dict = {
									audit_item : itm
								}
								result_dict.update(d)
								yield result_dict
								itm.clear()
								result_dict.clear()
			return
	
	def xml_to_dict(self, element):
		d = OrderedDict()

		if len(element) > 0:
			for child_element in element:
				rc_element_dict = self.xml_to_dict(child_element)
				sub_value = rc_element_dict[child_element.tag]

				if child_element.tag in d:
					if isinstance(d[child_element.tag], list):
						d[child_element.tag].append(sub_value)
					else:
						d[child_element.tag] = [d[child_element.tag], sub_value]
				else:
					d[child_element.tag] = sub_value

			return {element.tag : d}
		else:
			return {element.tag : element.text}
