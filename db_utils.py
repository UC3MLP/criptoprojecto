import sqlite3

DB_PATH = "votes_app.db"

def db_init():
    con = sqlite3.connect("votes_app.db") # creating database
    cur = con.cursor()                    # creating necessary cursor
    cur.execute("CREATE TABLE IF NOT EXISTS users(email TEXT UNIQUE, "
                "dni TEXT UNIQUE, salt BLOB, pwd_hash BLOB, iterations "
                "INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS tokens(token_hash TEXT PRIMARY "
                "KEY, election_id TEXT, used INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS tallies(election_id TEXT, "
                "choice_id TEXT)")
    con.commit()
    con.close()
