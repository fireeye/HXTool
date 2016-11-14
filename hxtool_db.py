import sqlite3

def sqlCreateProfileTable(c):
	c.execute('CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hostname TEXT)')

def sqlAddProfileItem(c, conn, name, hostname):
	c.execute("INSERT INTO profiles (name, hostname) VALUES (?, ?)", (name, hostname))
	conn.commit()

def sqlGetProfiles(c):
	c.execute('SELECT id, name, hostname from profiles')
	return(c.fetchall())

