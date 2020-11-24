#!/usr/bin/env python
# -*- coding: utf-8 -*-

# OpenIOC to Endpoint Security (HX) conversion code courtesy of Matthew Dunwoody

import xml.etree.ElementTree as et

import hxtool_logging

logger = hxtool_logging.getLogger(__name__)

# TODO: Load/cache from static/eventbuffer.json
valid_tokens = [
	'fileWriteEvent',
	'regKeyEvent',
	'ipv4NetworkEvent',
	'processEvent',
	'dnsLookupEvent',
	'imageLoadEvent',
	'urlMonitorEvent',
	'addressNotificationEvent'
]

def create_test(elem):
	context = elem.find('{http://openioc.org/schemas/OpenIOC_1.1}Context')
	content = elem.find('{http://openioc.org/schemas/OpenIOC_1.1}Content')
	
	test = {}
	
	# Handle value
	test['value'] = content.text
		
	# Handle type
	type = content.get('type').lower()
	if type == 'string' or type == 'date' or type == 'ip' or type == 'bool':
		test['type'] = 'text'
	elif type == 'int' or type == 'double':
		if ' TO ' in str(test['value']):
			test['type'] = 'range'
			test['value'] = '[' + test['value'] + ']'
		else:
			test['type'] = 'integer'
	else:
		test['type'] = type
	
	# Handle condition
	op = elem.get('condition')
	if test['type'] == 'range':
		test['operator'] = 'between'
	elif op.lower() == 'is':
		test['operator'] = 'equal'
	else:
		test['operator'] = op
	
	# Handle negation and preserve case
	if elem.get('negate').lower() == 'true':
		test['negate'] = True
	if elem.get('preserve-case').lower() == 'true':
		test['preservecase'] = True
	
	# Handle token. Convert token syntax from IOC format to API format
	search = context.get('search')
	search = search.replace('eventItem/', '')
	test['token'] = search
	
	return test


# TODO: Refactor this so that we don't have to iterate over tests again in process_ioc() to fail on unsupported tokens			
def generate_conditions(elem):
	child_ind = elem.findall('{http://openioc.org/schemas/OpenIOC_1.1}Indicator')
	child_item = elem.findall('{http://openioc.org/schemas/OpenIOC_1.1}IndicatorItem')
	op = elem.get('operator')
	
	conds = []
	
	# handle OR logic
	if op == 'OR':
		# recursively process child indicator and append result to conditions
		for ind in child_ind:
			conds.extend(generate_conditions(ind))
		
		# create new condition for each child indicatoritem and append to conditions
		for item in child_item:
			conds.append({'tests':[create_test(item)]})
		
	# handle AND logic
	elif op == 'AND':
		cond_list = []
		
		# recursively process child indicator and append result to conditions
		for ind in child_ind:
			cond_list.append(generate_conditions(ind))
			
		# add all child indicatoritem elements to a new condition
		tests = []
		for item in child_item:
			tests.append(create_test(item))
		if tests != []:
			cond_list.append([{'tests':tests}])
			
		conds = cond_list[0]
		
		# generate cartesian product of all conditions lists, if more than one exists
		if len(cond_list) > 1:
			for cond in cond_list[1:]:
				cond_temp = []
				
				for co in conds:
					co = co['tests']
					for c in cond:
						c = c['tests']
						cond_temp.append({'tests':co + c})
				conds = cond_temp
		
	 # should only be called with indicatoritem elements
	else:
		logger.warning('Something is broken in "generate_conditions"')
	
	# return result
	return conds

def generate_indicator(root):
	m = root.find('{http://openioc.org/schemas/OpenIOC_1.1}metadata')
	meta = {}
	
	# Grab metadata from IOC
	t = m.find('{http://openioc.org/schemas/OpenIOC_1.1}short_description')
	if t != None:
		meta['display_name'] = t.text
		meta['name'] = t.text
	t = m.find('{http://openioc.org/schemas/OpenIOC_1.1}description')
	if t != None:
		meta['description'] = t.text
	t = m.find('{http://openioc.org/schemas/OpenIOC_1.1}authored_by')
	if t != None:
		meta['create_text'] = t.text
	links = {}
	t = m.find('{http://openioc.org/schemas/OpenIOC_1.1}links')
	if t:
		for link in t:
			links[link.get('rel')] = link.text
		meta['meta'] = links
	
	
	platform = []
	# Parse OS metadata from IOC, if present
	for l in links.keys():
		if l.lower().strip() == 'platform':
			p = links[l].split(',')
			for pl in p:
				pl = pl.lower().strip()
				if pl.startswith('w'):
					if 'win' not in platform:
						platform.append('win')
				elif pl.startswith('o') or pl.startswith('m'):
					if 'osx' not in platform:
						platform.append('osx')
				elif pl.startswith('l'):
					if 'linux' not in platform:
					   platform.append('linux')
	
	if len(platform) > 0:
		meta['platforms'] = platform
	else:
		# Assume all platforms
		meta['platforms'] = [ 'win', 'osx', 'linux' ]
		logger.info("No platform data found in {}, assuming all platforms.".format(root.get('id')))
		
	return meta
	
#Parse IOC
def process_ioc(ioc):
	root = ioc.getroot()
	indicator_id = root.get('id')
	indicator = {
		indicator_id : {
			'presence' : [],
			'execution' : []
		}
	}
	
	# Generate indicator data
	ind = generate_indicator(root)
	try: 
		ind['display_name'].encode('ascii')
	except:
		logger.warning('Unicode name identified in IOC ' + root.get('id') + '. Skipping, please rename using ASCII.')
		return None

	indicator[indicator_id].update(ind)
	
	# Generate conditions
	top_or = root.find('{http://openioc.org/schemas/OpenIOC_1.1}criteria')[0]
	conditions = generate_conditions(top_or)
	if conditions:
		for cond in conditions:
			cond = cond['tests']
			sample_token = cond[0]['token']
			if sample_token.split('/')[0] in valid_tokens:
				if 'fileWriteEvent' or 'regKeyEvent' in sample_token:
					indicator[indicator_id]['presence'].append(cond)
				else:
					indicator[indicator_id]['execution'].append(cond)					
			else:
				logger.warning('{} contains unsupported token {}, skipping.'.format(indicator_id, cond[0]['token']))
				return None	
	else:
		logger.warning('No conditions parsed for IOC ' + root.get('id') + '. Skipping.')
		return None
		
	return indicator

def openioc_to_hxioc(xml_content):
	et.register_namespace('xsd','http://www.w3.org/2001/XMLSchema')
	et.register_namespace('xsi','http://www.w3.org/2001/XMLSchema-instance')
	et.register_namespace('','http://openioc.org/schemas/OpenIOC_1.1')
	
	try:
		openioc_xml = et.ElementTree(et.fromstring(xml_content))
		return process_ioc(openioc_xml)
	except Exception as e:
		logger.warning('OpenIOC 1.1 indicator parsing failed with exception: {}'.format(e))
		return None