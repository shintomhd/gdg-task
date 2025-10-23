# Testing file to see if the items are written to the database
import sqlite3

connection = sqlite3.connect('instance/db.sqlite')

cursor = connection.cursor()

cursor.execute("SELECT * FROM users;")

rows = cursor.fetchall()
if len(rows) == 0:
    print("Nothing to show")
    exit()
for row in rows:
    print(row)
