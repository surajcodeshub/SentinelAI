import sqlite3, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
db = 'sentinelai.db'
conn = sqlite3.connect(db)
conn.execute('DROP TABLE IF EXISTS users')
conn.commit()
conn.close()
print("Users table reset. Run app.py now.")
