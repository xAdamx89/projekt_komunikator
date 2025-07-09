import os
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

load_dotenv()

DBNAME = os.getenv("DBNAME")
HOST = os.getenv("HOST")
PORT = int(os.getenv("DB_PORT", 5432))
USER = os.getenv("USER")
PASSWD = os.getenv("PASSWD")

def get_connection():
    return psycopg2.connect(
        dbname=DBNAME,
        user=USER,
        password=PASSWD,
        host=HOST,
        port=PORT
    )