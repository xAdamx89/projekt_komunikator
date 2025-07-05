from fastapi import FastAPI, HTTPException
from models import RegisterRequest, LoginRequest
from db import db
import bcrypt
from dotenv import load_dotenv
import datetime
import jwt
import os
from dotenv import load_dotenv


#fastapi dev main.py - żeby uruchomić z terminala
#uvicorn main:app --reload alternatywa
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World!"}

@app.get("/getusers")
async def getusers():
    try:
        result = db.query("SELECT * FROM users")
        users = result.dictresult()
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd pobierania użytkowników: {str(e)}")

@app.post("/register")
async def register_user(request: RegisterRequest):
    existing = db.query("SELECT * FROM users WHERE login = $1", (request.login,))
    if existing:
        raise HTTPException(status_code=400, detail="Użytkownik o tym loginie już istnieje.")

    hashed_pw = bcrypt.hashpw(request.passwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    db.insert('users', fullname=request.fullname, login=request.login,password=hashed_pw, email=request.email)

    return {"message": "Użytkownik zarejestrowany pomyślnie"}

@app.post("/login")
async def login(request: LoginRequest):
    user = db.query("SELECT * FROM users WHERE login = $1", (request.login,))
    if not user:
        raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")
    
    user_data = user.dictresult()[0]
    hashed = user_data["password"]
    
    if not bcrypt.checkpw(request.password.encode('utf-8'), hashed.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")
    
    payload = {
        "user_id": user_data["id"],
        "login": user_data["login"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    load_dotenv()

    KEY = os.getenv("KEY")
    
    token = jwt.encode(payload, KEY, algorithm="HS256")
    
    return {"access_token": token, "token_type": "barer"}