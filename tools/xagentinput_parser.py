import json

myjson = {}

with open('../../xagtinput.json') as f:
	data = json.load(f)

for key in ['modules-audits', 'modules-acquisitions']:
	for module in data[key]:

		for mymodule, val in module.items():
			
			myjson[val['module name']] = {}
			myjson[val['module name']]['description'] = val['usage']
			myjson[val['module name']]['platforms'] = val['platform']
			myjson[val['module name']]['parameters'] = []

			for parameter in val['parameters']:

				myparam = parameter
				myparam['platforms'] = ["win", "osx", "linux"]

				textlist = ["String", "ByteSize", "FilePath", "Numeric", "PID", "RegistryPath", "dateTime"]

				if parameter['required'] == "true":
					myparam['required'] = True
				elif parameter['required'] == "false":
					myparam['required'] = False

				if parameter['repeatable'] == "true":
					myparam['repeatable'] = True
				elif parameter['repeatable'] == "false":
					myparam['repeatable'] = False

				if parameter['type'] in textlist:
					myparam['type'] = "text"
				elif parameter['type'] == "Bool":
					myparam['type'] = "dropdown"
					myparam['values'] = ['true', 'false']
				elif parameter['type'] == "ArrayOfString":
					myparam['type'] = "textarea"

				myjson[val['module name']]['parameters'].append(myparam)


print(json.dumps(myjson, indent=4, sort_keys=True))