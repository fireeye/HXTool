
def formatListSearches(s):
	x = "<table id='searchTable' class='tableData' style='width: 100%;'>"
	x += "<thead>"
	x += "<tr class='tableHeaderRow'>"
	x += "<td>id</td>"
	x += "<td>input type</td>"
	x += "<td>created at</td>"
	x += "<td>host-set</td>"
	x += "<td>state</td>"
	x += "<td># hosts</td>"
	x += "<td># Complete</td>"
	x += "<td># Queued</td>"
	x += "<td># Failed</td>"
	x += "<td># Matched</td>"
	x += "<td># Not matched</td>"
	x += "</tr>"
	x += "</thead>"
	x += "<tbody>"

	for entry in s['data']['entries']:
		x += "<tr class='tableDataRow clickable-row' data-href='/searchresult?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + entry['input_type'] + "</td>"
		x += "<td>" + entry['create_time'] + "</td>"
		x += "<td>" + entry['host_set']['name'] + "</td>"
		x += "<td>" + entry['state'] + "</td>"
		x += "<td>" + str(entry['stats']['hosts']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + str(entry['stats']['search_state']['MATCHED']) + "</td>"
		x += "<td>" + str(entry['stats']['search_state']['NOT_MATCHED']) + "</td>"
		x += "</tr>"

	x += "</tbody>"
	x += "</table>"
	return (x)


def formatSearchResults(hostresults):

	x = "<table id='resultsTable' class='tableData' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr class='tableHeaderRow'>"
        x += "<td style='width: 100px;'>host</td>"
	x += "<td style='width: 100px;'>type</td>"
	x += "<td>data</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in hostresults['data']['entries']:
		for result in entry['results']:
			x += "<tr>"
			x += "<td>" + entry['host']['hostname'] + "</td>"
			x += "<td>" + result['type'] + "</td>"
			x += "<td>"
			for data in result['data']:
				x += "<b>" + data + ":</b> " + str(result['data'][data]) + " "
			x += "</td>"
                	x += "</tr>"

        x += "</tbody>"
        x += "</table>"
        return (x)


def formatBulkTable(bulktable):

        x = "<table id='bulkTable' class='tableData' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr class='tableHeaderRow'>"
        x += "<td style='width: 100px;'>id</td>"
        x += "<td style='width: 100px;'>state</td>"
        x += "<td>host set</td>"
        x += "<td>New</td>"
        x += "<td>Queued</td>"
        x += "<td>Failed</td>"
        x += "<td>Complete</td>"
        x += "<td>Aborted</td>"
        x += "<td>Deleted</td>"
        x += "<td>Refresh</td>"
        x += "<td>Cancelled</td>"
        x += "<td>% Complete</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in bulktable['data']['entries']:

		total_size = entry['stats']['running_state']['NEW'] + entry['stats']['running_state']['QUEUED'] + entry['stats']['running_state']['FAILED'] + entry['stats']['running_state']['ABORTED'] + entry['stats']['running_state']['DELETED'] + entry['stats']['running_state']['REFRESH'] + entry['stats']['running_state']['CANCELLED'] + entry['stats']['running_state']['COMPLETE']
		completerate = (entry['stats']['running_state']['COMPLETE'] / float(total_size)) * 100

		x += "<tr class='tableDataRow clickable-row' data-href='/bulkdetails?id=" + str(entry['_id']) + "'>"
		x += "<td>" + str(entry['_id']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>" + str(entry['host_set']['name']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['NEW']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['QUEUED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['FAILED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['COMPLETE']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['ABORTED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['DELETED']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['REFRESH']) + "</td>"
		x += "<td>" + str(entry['stats']['running_state']['CANCELLED']) + "</td>"
		x += "<td>" + str(completerate) + " %</td>"
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"
        return (x)

def formatBulkHostsTable(hoststable):

        x = "<table id='bulkTable' class='tableData' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr class='tableHeaderRow'>"
        x += "<td style='width: 100px;'>hostname</td>"
        x += "<td style='width: 100px;'>queued at</td>"
        x += "<td style='width: 100px;'>completed at</td>"
        x += "<td style='width: 100px;'>state</td>"
        x += "<td>actions</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"


	for entry in hoststable['data']['entries']:
		x += "<tr class='tableDataRow'>"
		x += "<td>" + str(entry['host']['hostname']) + "</td>"
		#x += "<td>" + str(entry['host']['_id']) + "</td>"
		x += "<td>" + str(entry['queued_at']) + "</td>"
		x += "<td>" + str(entry['complete_at']) + "</td>"
		x += "<td>" + str(entry['state']) + "</td>"
		x += "<td>"
		if str(entry['state']) == "COMPLETE":
			x += "<a href='/bulkdownload?id=" + str(entry['result']['url']) + "'>Download acquisition</a>"
		x += "</td>"
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"
        return (x)


def formatIOCResults(iocs):

	x = "<table id='iocTable' class='tableData' style='font-size: 13px; width: 100%;'>"
        x += "<thead>"
        x += "<tr class='tableHeaderRow'>"
        x += "<td>Name</td>"
        x += "<td style='width: 100px;'>Active since</td>"
        x += "<td style='width: 100px;'>Created by</td>"
        x += "<td style='width: 100px;'>Category</td>"
        x += "<td style='width: 100px;'>Active conditions</td>"
        x += "<td style='width: 100px;'>Hosts with alerts</td>"
        x += "</tr>"
        x += "</thead>"
        x += "<tbody>"

	for entry in iocs['data']['entries']:
		x += "<tr class='tableDataRow'>"
		x += "<td>" + str(entry['name']) + "</td>"
		x += "<td>" + str(entry['active_since']) + "</td>"
		x += "<td>" + str(entry['create_actor']['username']) + "</td>"
		x += "<td>" + str(entry['category']['name']) + "</td>"
		x += "<td>" + str(entry['stats']['active_conditions']) + "</td>"
		x += "<td>" + str(entry['stats']['alerted_agents']) + "</td>"
		x += "</tr>"

        x += "</tbody>"
        x += "</table>"
        return (x)

def formatCategoriesSelect(cats):

	x = "<select name='cats' id='cats'>"
	for entry in cats['data']['entries']:
		x += "<option value='" + entry['uri_name'] + "'>" + entry['name']
	x += "</select>"
	return(x)

