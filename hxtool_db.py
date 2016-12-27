import sqlite3

def sqlCreateTables(c):
	sqlCreateProfileTable(c)
	sqlCreateAlertsTable(c)
	sqlCreateAnnotationTable(c)

def sqlCreateProfileTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hostname TEXT)')

def sqlCreateAlertsTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, profileid INTEGER, hxalertid INTEGER)')

def sqlCreateAnnotationTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS annotation(id INTEGER PRIMARY KEY AUTOINCREMENT, alertid INTEGER, text TEXT, state INTEGER)')

	
# Profiles
def sqlAddProfileItem(c, conn, name, hostname):
	c.execute("INSERT INTO profiles (name, hostname) VALUES (?, ?)", (name, hostname))
	conn.commit()

def sqlGetProfiles(c):
	c.execute('SELECT id, name, hostname from profiles')
	return(c.fetchall())
	
# Alerts
def sqlAddAlert(c, conn, profileid, hxalertid):
	c.execute("INSERT INTO alerts (profileid, hxalertid) VALUES (?, ?)", (profileid, hxalertid))
	conn.commit()
	return(c.lastrowid)

# Annotation
def sqlAddAnnotation(c, conn, alertid, text, state):
	c.execute("INSERT INTO annotation (alertid, text, state) VALUES (?, ?, ?)", (alertid, text, state))
	conn.commit()

def sqlGetAnnotations(c, conn, alertid, profileid):
	c.execute("SELECT annotation.text, annotation.state from annotation, alerts where alerts.id = annotation.alertid and alerts.hxalertid = ? and alerts.profileid = ?", (alertid, profileid))
	return(c.fetchall())
	
def sqlGetAnnotationStats(c, conn, alertid, profileid):
	c.execute("SELECT count(annotation.text), max(annotation.state) from annotation, alerts where alerts.id = annotation.alertid and alerts.hxalertid = ? and alerts.profileid = ?", (alertid, profileid))
	return(c.fetchall())
	
