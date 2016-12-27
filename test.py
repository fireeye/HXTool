from hxtool_db import *
import sqlite3

conn = sqlite3.connect('hxtool.db')
c = conn.cursor()

# sqlCreateTables(c)

alertid = 52
profileid = 1

##c.execute("SELECT annotation.text, annotation.state from annotation, alerts where alerts.id = annotation.alertid and alerts.profileid = ?", (profileid))
c.execute("SELECT alerts.hxalertid, annotation.text, annotation.state from annotation, alerts where alerts.id = annotation.alertid and alerts.hxalertid = ? and alerts.profileid = ?", (alertid, profileid))
print c.fetchall()



