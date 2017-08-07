#!/usr/bin/env python
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
from pandas import DataFrame
import hashlib

class hxtool_data_models:
	def __init__(self, stack_type):
		self._stack_type = self.stack_types[stack_type]
	
	def xml_to_dict(self, hostname, results_xml):
		xml_items = ET.fromstring(results_xml).findall('./{0}'.format(self._stack_type['item_name']))
		items = []
		for xml_item in xml_items:
			item = {"hostname" : hostname}
			for e in xml_item:
				if e.tag in self._stack_type['fields']:
					item[e.tag] = e.text.encode('utf-8')
					
			if self._stack_type['post_process']:
				item = self._stack_type['post_process'](item, xml_item)
				
			items.append(item)	
		return items
	
	def stack_data(self, data, index = None, group_by = None):
		if not index:
			index = self._stack_type['default_index']
		if not group_by:
			group_by = self._stack_type['default_groupby']
			
		data_frame = DataFrame(data).astype(unicode)
		data_frame.replace('nan', '', inplace = True)
		data_frame = data_frame.groupby(by = group_by, as_index = False).apply(lambda _: list(_[index])).reset_index(name = index)
		data_frame['count'] = data_frame[index].apply(lambda _: len(_))
		data_frame.sort_values(by = 'count', ascending = False, inplace = True)
		return data_frame.to_json(orient = 'records')
	
	def w32mbr_post_process(self, item, xml_item):
		# TODO: implement mbr hashing
		pass

	stack_types = {
		"windows-services": {
			"audit_module" : "w32services",
			"script": "services-md5.xml",
			"platform": "windows",
			"name" : "Services MD5",
			"item_name": "ServiceItem",
			"fields": [
				"name",
				"descriptiveName",
				"description",
				"mode",
				"startedAs",
				"path",
				"pathmd5sum",
				"arguments",
				"serviceDLL",
				"serviceDLLmd5sum",
				"status",
				"pid",
				"type"
				],
			"default_index": "hostname",
			"default_groupby": ["name", "path", "pathmd5sum", "serviceDLL", "serviceDLLmd5sum"],
			"post_process": None
		},
		"windows-drivermodules": {
			"audit_module" : "w32drivers-modulelist",
			"script" : "w32drivers-modulelist.xml",
			"platform" : "windows",
			"name" : "Driver Modules",
			"item_name" : "",
			"fields" : [
				"ModuleName",
				"ModuleInit",
				"ModuleAddress",
				"ModuleSize",
				"ModuleBase",
				"ModulePath",
			],
			"default_index" : "hostname",
			"default_groupby" : ["ModuleName", "ModuleSize", "ModulePath"],
			"post_process" : None
		},
		"windows-driversignature": {
			"audit_module" : "w32drivers-signature",
			"script" : "w32drivers-signature.xml",
			"platform" : "windows",
			"name" : "Driver Signature",
			"item_name" : "",
			"fields" : [
				"ImageSize",
				"DriverObjectAddress",
				"DriverName",
				"DriverUnload",
				"Sha256sum",
				"DeviceItem",
				"Md5sum",
				"PEInfo",
				"DriverStartIo",
				"DriverInit",
				"ImageBase",
				"Sha1sum",
			],
			"default_index" : "hostname",
			"default_groupby" : ["DriverName", "Md5sum", "Sha1sum"],
			"post_process" : None
			
		},
		"windows-ports": {
			"audit_module" : "w32ports",
			"script": "w32ports.xml",
			"platform": "windows",
			"name" : "Ports",
			"item_name": "",
			"fields": [
				"remotePort",
				"protocol",
				"localPort",
				"process",
				"pid",
				"localIP",
				"state",
				"remoteIP",
				"path"
			],
			"default_index": "hostname",
			"default_groupby": ['path', 'localPort', 'state', 'remoteIP', 'remotePort'],			
			"post_process": None
		},
		"windows-processes": {
			"audit_module" : "w32processes-memory",
			"script" : "w32processes-memory.xml",
			"platform" : "windows",
			"name" : "Process",
			"item_name" : "",
			"fields" : [
				"Username",
				"SectionList",
				"name",
				"parentpid",
				"PortList",
				"HandleList",
				"pid",
				"SecurityType",
				"kernelTime",
				"SecurityID",
				"arguments",
				"startTime",
				"path",
				"userTime"
				],
			"default_index" : "hostname",
			"default_groupby" : ["name", "path", "arguments"],			
			"post_process" : None
		},
		"windows-tasks": {
			"audit_module" : "w32tasks",
			"script": "w32tasks.xml",
			"platform": "windows",
			"name" : "Task",
			"item_name": "",
			"fields": [
				"Status",
				"Name",
				"Creator",
				"MaxRunTime",
				"AccountName", 
				"AccountLogonType", 
				"MostRecentRunTime", 
				"Flag", 
				"AccountRunLevel", 
				"NextRunTime", 
				"ActionList", 
				"TriggerList", 
				"VirtualPath", 
				"ExitCode", 
				"CreationDate", 
				"Comment"
				],
			"default_index": "hostname",
			"default_groupby": ["Name", "Creator", "AccountLogonType", "ActionList"],
			"post_process": None
		},
		"windows-mbr" : {
			"audit_module" : "w32disk-acquisition",
			"script" : "w32mbr.xml",
			"platform" : "windows",
			"name" : "Master Boot Record",
			"item_name" : "",
			"fields" : [],
			"default_index" : "hostname",
			"default_groupby" : ["Md5sum", "Sha1sum", "Sha256sum"],
			"post_process" : w32mbr_post_process
		}
	}
	
