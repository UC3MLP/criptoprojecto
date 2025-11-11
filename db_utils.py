import sqlite3

DB_PATH = "votes_app.db"

def db_init():
    con = sqlite3.connect("votes_app.db") # creating database
    cur = con.cursor()                    # creating necessary cursor
    cur.execute("CREATE TABLE IF NOT EXISTS users(email TEXT UNIQUE, "
                "dni BLOB, salt BLOB, pwd_hash BLOB, iterations "
                "INTEGER)")
    # for saving users
    cur.execute("CREATE TABLE IF NOT EXISTS tokens(token_hash TEXT PRIMARY "
                "KEY, election_id TEXT, used INTEGER, dni TEXT, UNIQUE(dni, "
                "election_id))")
    # for saving tokens from auth server
    cur.execute("CREATE TABLE IF NOT EXISTS tallies(id INTEGER PRIMARY KEY AUTOINCREMENT, election_id TEXT NOT NULL, "
                "choice_id TEXT NOT NULL, signature BLOB  NOT NULL)")
    # for saving anonymous votes
    con.commit()
    con.close()
