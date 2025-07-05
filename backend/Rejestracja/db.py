import os
from pg import DB
from dotenv import load_dotenv

load_dotenv()

DBNAME = os.getenv("DBNAME")
HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT"))
USER = os.getenv("USER")
PASSWD = os.getenv("PASSWD")

db = DB(dbname=DBNAME, host=HOST, port=PORT, user=USER, passwd=PASSWD)

def gettables():
    return db.get_tables()