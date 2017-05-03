import sqlite3
from hx_lib import *

# Creates all tables at launch if they don't exist
def sqlCreateTables(c):
	sqlCreateProfileTable(c)
	sqlCreateAlertsTable(c)
	sqlCreateAnnotationTable(c)
	sqlCreateProfileCredTable(c)
	sqlCreateStackTable(c)
	sqlCreateStackServiceMD5Table(c)


# Table creation functions
#################

# Profile table - used to store HX profiles for different tasks
def sqlCreateProfileTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hostname TEXT)')

# Alerts table - used to map hx alerts with hxtool alerts if annotated
def sqlCreateAlertsTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, profileid INTEGER, hxalertid INTEGER)')

# Annotation - used to store event annotations
def sqlCreateAnnotationTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS annotation(id INTEGER PRIMARY KEY AUTOINCREMENT, alertid INTEGER, text TEXT, state INTEGER, ctime datetime default current_timestamp, cuser TEXT)')

# Profile credentials table - used to store hx api credentials for background processing (enables stacking)
def sqlCreateProfileCredTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS profcreds(id INTEGER PRIMARY KEY AUTOINCREMENT, profileid INTEGER, hxuser TEXT, hxpass TEXT)')

# Stacking table - used to store information on stacking jobs (bulk acquistiions)
def sqlCreateStackTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS stacktable(stackid INTEGER PRIMARY KEY AUTOINCREMENT, cdate datetime default current_timestamp, udate datetime default current_timestamp, type TEXT, state TEXT, profileid INTEGER, bulkid INTEGER, hostset INTEGER, c_rate TEXT)')

# Stacking results table for Services MD5 hash
def sqlCreateStackServiceMD5Table(c):
	c.execute('CREATE TABLE IF NOT EXISTS svcmd5(id INTEGER PRIMARY KEY AUTOINCREMENT, stackid INTEGER, hostname TEXT, name TEXT, descriptiveName TEXT, description TEXT, mode TEXT, path TEXT, pathmd5sum TEXT, arguments TEXT, status TEXT, pid INTEGER, type TEXT, serviceDLL TEXT, serviceDLLmd5sum TEXT, startedAs TEXT)')
	
# SQL based authentication
def restAuthProfile(c, conn, profileid):
	c.execute("SELECT hxuser, hxpass FROM profcreds WHERE profileid = (?)", (str(profileid)))
	profcreds = c.fetchall()
	for cred in profcreds:
		hxuser = cred[0]
		hxpass = cred[1]
	
	c.execute("SELECT hostname FROM profiles where id = (?)", (str(profileid)))
	prof = c.fetchall()
	for pro in prof:
		hxip = pro[0]
	
	token = restAuth(hxip, "3000", hxuser, hxpass)
	return(token, hxip)

# Profiles related queries
################

def sqlAddProfileItem(c, conn, name, hostname):
	c.execute("INSERT INTO profiles (name, hostname) VALUES (?, ?)", (name, hostname))
	conn.commit()

def sqlGetProfiles(c):
	c.execute('SELECT id, name, hostname from profiles')
	return(c.fetchall())

def sqlGetProfCredTable(c, conn, profileid):
	c.execute('SELECT id, hxuser, hxpass from profcreds where profileid = (?)', (str(profileid)))
	return(c.fetchall())

	
# Profile credential related queries
######################
	
def sqlInsertProfCredsInfo(c, conn, profileid, bguser, bgpass):
	c.execute("INSERT INTO profcreds (profileid, hxuser, hxpass) VALUES(?, ?, ?)", (profileid, bguser, bgpass))
	conn.commit()

def sqlDeleteProfCredsInfo(c, conn, profileid):
	c.execute("DELETE FROM profcreds where profileid = (?)", (profileid))
	conn.commit()

	
# Alerts and annotations
################

def sqlAddAlert(c, conn, profileid, hxalertid):
	c.execute("INSERT INTO alerts (profileid, hxalertid) VALUES (?, ?)", (profileid, hxalertid))
	conn.commit()
	return(c.lastrowid)

def sqlAddAnnotation(c, conn, alertid, text, state, user):
	c.execute("INSERT INTO annotation (alertid, text, state, cuser) VALUES (?, ?, ?, ?)", (alertid, text, state, user))
	conn.commit()

def sqlGetAnnotations(c, conn, alertid, profileid):
	c.execute("SELECT annotation.text, annotation.state, annotation.ctime, annotation.cuser from annotation, alerts where alerts.id = annotation.alertid and alerts.hxalertid = ? and alerts.profileid = ?", (alertid, profileid))
	return(c.fetchall())
	
def sqlGetAnnotationStats(c, conn, alertid, profileid):
	c.execute("SELECT count(annotation.text), max(annotation.state) from annotation, alerts where alerts.id = annotation.alertid and alerts.hxalertid = ? and alerts.profileid = ?", (alertid, profileid))
	return(c.fetchall())
	
# Stacking related queries
#################

def sqlAddStackJob(c, conn, profileid, type, hostset):
	c.execute("INSERT INTO stacktable (type, state, profileid, hostset, c_rate) VALUES (?, ?, ?, ?, ?)", (type, "SCHEDULED", profileid, hostset, 0))
	conn.commit()

def sqlDeleteStackJob(c, conn, profileid, stackid):
	c.execute("DELETE FROM stacktable where profileid = (?) and stackid = (?)", (profileid, stackid))
	conn.commit()

def sqlGetStackJobs(c, conn, profileid):
	c.execute("SELECT stackid, cdate, udate, type, state, profileid, bulkid, hostset, c_rate from stacktable where profileid = (?)", (profileid))
	return(c.fetchall())

def sqlGetStackJobsProfile(c, conn, profileid):
	c.execute("SELECT stackid, cdate, udate, type, state, profileid, bulkid, hostset, c_rate from stacktable where profileid = (?)", (profileid))
	return(c.fetchall())
	
def sqlChangeStackJobState(c, conn, stackid, profileid, state):
	c.execute("UPDATE stacktable set state = (?) where profileid = (?) and stackid = (?)", (state, profileid, stackid))
	conn.commit()

def sqlGetStackJobs(c, conn):
	c.execute("SELECT stackid, type, state, profileid, bulkid, hostset, c_rate FROM stacktable")
	return(c.fetchall())

def sqlUpdateStackJobSubmitted(c, conn, stackid, bulkid):
	c.execute("UPDATE stacktable SET bulkid = (?), state = (?) WHERE stackid = (?)", (bulkid, "SUBMITTED", stackid))
	conn.commit()
	
def sqlUpdateStackJobState(c, conn, stackid, state):
	c.execute("UPDATE stacktable SET state = (?) WHERE stackid = (?)", (state, stackid))
	conn.commit()

def sqlGetStackJobsForBulkId(c, conn, profileid, bulkid):
	c.execute("SELECT stackid, bulkid, profileid FROM stacktable WHERE profileid = (?) and bulkid = (?)", (profileid, bulkid))
	return(c.fetchall())

def sqlUpdateStackJobProgress(c, conn, stackid, completerate):
	c.execute("UPDATE stacktable SET c_rate = (?) WHERE stackid = (?)", (completerate, stackid))
	conn.commit()

# ServiceMD5 hash functions
def sqlAddStackServiceMD5(c, conn, stackid, hostname, stackdata):
	for item in stackdata:
		if not item.has_key('pathmd5sum'):
			item['pathmd5sum'] = None
		if not item.has_key('serviceDLL'):
			item['serviceDLL'] = None
		if not item.has_key('serviceDLLmd5sum'):
			item['serviceDLLmd5sum'] = None
			
		c.execute("INSERT INTO svcmd5(stackid, hostname, name, descriptiveName, description, mode, path, pathmd5sum, arguments, status, pid, type, serviceDLL, serviceDLLmd5sum, startedAs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (stackid, hostname, item['name'], item['descriptiveName'], item['description'], item['mode'], item['path'], item['pathmd5sum'], item['arguments'], item['status'], item['pid'], item['type'], item['serviceDLL'], item['serviceDLLmd5sum'], item['startedAs']))
	conn.commit()

def sqlQueryStackServiceMD5(c, conn, stackid, hostname):
	c.execute("SELECT id FROM svcmd5 WHERE stackid = (?) AND hostname = (?) LIMIT 1", (stackid, hostname))
	if c.fetchone():
		return(True)
	else:
		return(False)

def sqlDeleteStackServiceMD5(c, conn, stackid):
	c.execute("DELETE from svcmd5 WHERE stackid = (?)", (str(stackid)))
	conn.commit()
	
def sqlGetServiceMD5StackData(c, conn, stackid):
	c.execute("SELECT count(*) as count, name, path, pathmd5sum, serviceDLL, serviceDLLmd5sum, hostname from svcmd5 where stackid = (?) group by name, path, pathmd5sum, serviceDLL, serviceDLLmd5sum order by count desc", (stackid))
	return(c.fetchall())
	