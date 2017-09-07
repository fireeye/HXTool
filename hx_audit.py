import xml.etree.ElementTree as ET
import zipfile
import json

def get_mime_type(generator):
	return generator == 'w32disk-acquisition' and 'application/octet-stream' or 'application/xml'

def get_audit(acquisition_package_path, generator):
	mime_type = get_mime_type(generator)
	with zipfile.ZipFile(acquisition_package_path) as f:
		acquisition_manifest = json.loads(f.read('manifest.json').decode('utf-8'))
		if 'audits' in acquisition_manifest:
			for audit in acquisition_manifest['audits']:
				if audit['generator'] == generator and 'results' in audit:
						for results in audit['results']:
							if results['type'] == mime_type:
								return f.read(results['payload'])
	return None

def get_audit_records(hostname, results_data, generator, item_name, fields=None, post_process=None):
	items = []
	mime_type = get_mime_type(generator)
	if mime_type == 'application/xml':		
		xml_items = ET.fromstring(results_data).findall('./{0}'.format(item_name))
		for xml_item in xml_items:
			item = {'hostname' : hostname}
			for e in xml_item:
				if fields and e.tag not in fields:
					continue
				# TODO: we only recurse 1 level deep - should recurse further
				if len(list(e)) > 0:
					item[e.tag] = []
					item[e.tag].append({_.tag : _.text for _ in e[0]})
				else:
					item[e.tag] = e.text
						
			if post_process:
				item.update(post_process(results_data))
				
			items.append(item)	
	elif mime_type == 'application/octet-stream' and post_process:
		item = {'hostname' : hostname}
		item.update(post_process(results_data))
		items.append(item)
	else:
		#TODO: Unexpected mime_type?
		pass
	return items

