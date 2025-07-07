from fastapi import FastAPI, HTTPException, Request, Depends
from models import LoginResponse, RegisterRequest, LoginRequest, PublicKeyRequest, User
from db import db
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer

load_dotenv()
KEY = os.getenv("KEY")
ALGORITHM = os.getenv("ALGORITHM")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


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
        user_id = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Nieprawidłowy token")

        result = db.query("SELECT * FROM users_token WHERE user_id = $1 AND token = $2 AND expires_at > NOW()", (user_id, token))
        if not result.dictresult():
            raise HTTPException(status_code=401, detail="Token jest nieważny lub został usunięty")

        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Nieprawidłowy token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Niepoprawny token")
    
    # Sprawdź, czy token ma wymagane pola
    if "id" not in payload or "login" not in payload or "email" not in payload:
        raise HTTPException(status_code=401, detail="Nieautoryzowany")
    
    return User(
        id=payload["id"],
        login=payload["login"],
        fullname=payload.get("fullname"),
        email=payload["email"]
    )

@app.get("/")
async def root():
    return {"message": "Hello World!"}

@app.get("/getusers")
async def getusers(current_user: int = Depends(verify_token)):
    try:
        result = db.query("SELECT * FROM users WHERE id != $1", (current_user,))
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
        "id": user_data["id"],
        "fullname": user_data["fullname"],
        "login": user_data["login"],
        "email": user_data["email"],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    
    token = jwt.encode(payload, KEY, algorithm="HS256")
    
    db.query("""
    INSERT INTO users_token (user_id, issued_at, expires_at, token)
    VALUES ($1, NOW(), NOW() + INTERVAL '1 hour', $2)
    """, (user_data["id"], token))
    
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
    try:
        payload = jwt.decode(token, KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Niepoprawny token")
    
    # Sprawdź, czy token ma wymagane pola
    if "id" not in payload or "login" not in payload or "email" not in payload:
        raise HTTPException(status_code=401, detail="Nieautoryzowany")
    
    return User(
        id=payload["id"],
        login=payload["login"],
        fullname=payload.get("fullname"),
        email=payload["email"]
    )

@app.post("/upload_public_key")
async def upload_public_key(request: PublicKeyRequest, user = Depends(get_current_user)):
    existing = db.query("SELECT id FROM encryption_keys WHERE user_id = $1", user.id)
    
    if existing:
        db.query(
            "UPDATE encryption_keys SET public_key = $1, created_at = $2 WHERE user_id = $3",
            request.public_key,
            datetime.utcnow(),
            user.id
        )
    else:
        db.query(
            "INSERT INTO encryption_keys (user_id, public_key, created_at) VALUES ($1, $2, $3)",
            user.id,
            request.public_key,
            datetime.utcnow()
        )

    return {"message": f"Klucz publiczny dla użytkownika {user.fullname} został zapisany."}

@app.get("/has_public_key")
async def has_public_key(user: User = Depends(get_current_user)):
    result = db.query("SELECT id FROM encryption_keys WHERE user_id = $1", user.id)
    key_exists = len(result) > 0
    return {"has_public_key": key_exists}

@app.get("/get_user_token", response_model=LoginResponse)
def get_user_token(login: str):
    try:
        # Pobierz ID użytkownika po loginie
        user = db.query("SELECT id FROM users WHERE login = $1", login)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = user[0][0]

        # Pobierz najnowszy token
        token_row = db.query("""
            SELECT token FROM users_token
            WHERE user_id = $1
            ORDER BY issued_at DESC
            LIMIT 1
        """, user_id)

        if token_row:
            return LoginResponse(access_token=token_row[0][0])  # <--- Zmiana tutaj
        else:
            raise HTTPException(status_code=404, detail="Token not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))