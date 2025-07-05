from fastapi import FastAPI, HTTPException, Request, Depends
from models import RegisterRequest, LoginRequest
from db import db
import bcrypt
from dotenv import load_dotenv
import datetime
import jwt
import os
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv("KEY")
ALGORITHM = os.getenv("ALGORITHM")

#fastapi dev main.py - żeby uruchomić z terminala
#uvicorn Rejestracja.main:app --host 0.0.0.0 --port 8001 --reload alternatywa
app = FastAPI()

def verify_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Brak lub niepoprawny nagłówek Authorization")

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Nieprawidłowy token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Nieprawidłowy token")



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
    
    user_id = user_data["id"]
    
    
    token = jwt.encode(payload, KEY, algorithm="HS256")
    
    db.query("""
    INSERT INTO users_token (user_id, issued_at, expires_at, token)
    VALUES ($1, NOW(), NOW() + INTERVAL '1 hour', $2)
    """, (user_id, token))
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/welcomepage")
async def get_all_users(current_user: int = Depends(verify_token)):
    try:
        users_result = db.query("SELECT id, fullname, email FROM users")
        users = users_result.dictresult()

        active_result = db.query("SELECT user_id FROM users_token")
        active_ids = {row["user_id"] for row in active_result.dictresult()}

        response = []
        for user in users:
            response.append({
                "fullname": user["fullname"],
                "email": user["email"],
                "is_active": user["id"] in active_ids
            })

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd serwera: {str(e)}")
    