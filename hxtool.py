#!/usr/bin/python

###########################################################
# hxTool v1.0                                             #
# Henrik Olsson                                           #
# henrik.olsson@fireeye.com                               #
###########################################################

from flask import Flask, request, session, redirect, render_template, send_file
from hx_lib import *
from hxtool_formatting import *
import base64
import json
import io
import os

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):

		alertsjson = restGetAlerts(session['ht_token'], '10', session['ht_ip'], '3000')
		alerts = formatDashAlerts(alertsjson, session['ht_token'], session['ht_ip'], '3000')
	
		stats = [{'value': 0, 'label': 'Exploit'}, {'value': 0, 'label': 'IOC'}]
		for alert in alertsjson['data']['entries']:
			if alert['source'] == "EXD":
				stats[0]['value'] = stats[0]['value'] + 1
			if alert['source'] == "IOC":
				stats[1]['value'] = stats[1]['value'] + 1

		stats[0]['value'] = stats[0]['value'] * 10
		stats[1]['value'] = stats[1]['value'] * 10

		return render_template('ht_index.html', session=session, alerts=alerts, iocstats=stats)
	else:
		return redirect("/login", code=302)

####
#### Search and Sweep

@app.route('/search', methods=['GET', 'POST'])
def search():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):

		# If we get a post it's a new sweep
		if request.method == 'POST':
			f = request.files['newioc']
			rawioc = f.read()
			b64ioc = base64.b64encode(rawioc)
			out = restSubmitSweep(session['ht_token'], session['ht_ip'], '3000', b64ioc)

		s = restListSearches(session['ht_token'], session['ht_ip'], '3000')
		searches = formatListSearches(s)
		return render_template('ht_searchsweep.html', session=session, searches=searches)
	else:
		return redirect("/login", code=302)

@app.route('/searchresult', methods=['GET'])
def searchresult():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
		if request.args.get('id'):
			hostresults = restGetSearchResults(session['ht_token'], request.args.get('id'), session['ht_ip'], '3000')
			res = formatSearchResults(hostresults)
	                return render_template('ht_search_dd.html', session=session, result=res)
        else:
                return redirect("/login", code=302)


####
#### Build a real-time indicator

@app.route('/buildioc', methods=['GET', 'POST'])
def buildioc():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):

		# New IOC to be created
		if request.method == 'POST':
#			print request.form['iocname']
#			print request.form['cats']

			iocuri = restAddIndicator('apia', request.form['iocname'], request.form['cats'], session['ht_token'], session['ht_ip'], '3000')

			condEx = []
			condPre = []

			for fieldname, value in request.form.items():
				if "cond_" in fieldname:
					condComp = fieldname.split("_")
					if (condComp[2] == "presence"):
						condPre.append(value.rstrip(","))
					elif (condComp[2] == "execution"):
						condEx.append(value.rstrip(","))

			for data in condPre:
				data = """{"tests":[""" + data + """]}"""
				data = data.replace('\\', '\\\\')
				res = restAddCondition(iocuri, "presence", data, request.form['cats'], session['ht_token'], session['ht_ip'], '3000')

			for data in condEx:
                                data = """{"tests":[""" + data + """]}"""
                                data = data.replace('\\', '\\\\')
                                res = restAddCondition(iocuri, "execution", data, request.form['cats'], session['ht_token'], session['ht_ip'], '3000')


		categories = restListIndicatorCategories(session['ht_token'], session['ht_ip'], '3000')
		cats = formatCategoriesSelect(categories)
		iocs = restListIndicators(session['ht_token'], session['ht_ip'], '3000')
		indicators = formatIOCResults(iocs)
		return render_template('ht_buildioc.html', session=session, cats=cats, indicators=indicators)
	else:
		return redirect("/login", code=302)

@app.route('/categories')
def categories():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
		return render_template('ht_categories.html', session=session)
	else:
		return redirect("/login", code=302)

@app.route('/export')
def exportioc():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
		return render_template('ht_export.html', session=session)
	else:
		return redirect("/login", code=302)

@app.route('/import')
def importioc():
	if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
		return render_template('ht_import.html', session=session)
	else:
		return redirect("/login", code=302)

####
#### Bulk Acqusiitions

@app.route('/bulk', methods=['GET', 'POST'])
def listbulk():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
		if request.method == 'POST':
                        f = request.files['bulkscript']
                        bulkscript = f.read()
			newbulk = restNewBulkAcq(session['ht_token'], bulkscript, request.form['bulkhostset'], session['ht_ip'], '3000')

		acqs = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], '3000')
		bulktable = formatBulkTable(acqs)
                return render_template('ht_bulk.html', session=session, bulktable=bulktable)
        else:
                return redirect("/login", code=302)

@app.route('/bulkdetails')
def bulkdetails():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
                # acqs = restListBulkAcquisitions(session['ht_token'], session['ht_ip'], '3000')
                # bulktable = formatBulkTable(acqs)
		if request.args.get('id'):
			# bulktable = request.args.get('id')

			hosts = restListBulkDetails(session['ht_token'], request.args.get('id'), session['ht_ip'], '3000')
			bulktable = formatBulkHostsTable(hosts)

	                return render_template('ht_bulk_dd.html', session=session, bulktable=bulktable)
        else:
                return redirect("/login", code=302)


@app.route('/bulkdownload')
def bulkdownload():
        if 'ht_user' in session and restIsSessionValid(session['ht_token'], session['ht_ip'], '3000'):
                if request.args.get('id'):
			urlhead, fname = os.path.split(request.args.get('id'))
			acq = restDownloadBulkAcq(session['ht_token'], request.args.get('id'), session['ht_ip'], '3000')
			return send_file(io.BytesIO(acq), attachment_filename=fname, as_attachment=True)
        else:
                return redirect("/login", code=302)


####
#### Authentication

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		print request.form['ht_ip']
		(resp, message) = restValidateAuth(request.form['ht_ip'], '3000', request.form['ht_user'], request.form['ht_pass'])
		if resp:
			session['ht_user'] = request.form['ht_user']
			session['ht_ip'] = request.form['ht_ip']
			session['ht_token'] = message
			return redirect("/", code=302)
		else:
			# return redirect("/login?fail=1", code=302)
			print message
			return render_template('ht_login.html', fail=message)
	else:
		# return app.send_static_file('ht_login.html')
		return render_template('ht_login.html')

@app.route('/logout')
def logout():
	session.pop('ht_user', None)
	return redirect("/", code=302)

app.secret_key = 'A0Zr98j/3yX23R~XH1212jmN]Llw/,?RT'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
