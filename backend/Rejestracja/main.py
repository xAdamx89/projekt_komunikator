from fastapi import FastAPI, HTTPException, Request, Depends
from models import PublicKeyRequestByUserid, PublicKeyRequest, MessageSendRequest, MessageResponse, ConversationRequest, LoginResponse, RegisterRequest, LoginRequest, PublicKeyRequest, User
from db import db
from db2 import get_connection
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
from psycopg2.extras import RealDictCursor
import psycopg2
from fastapi import Query

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

        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT user_id, token, expires_at 
                    FROM users_token 
                    WHERE user_id = %s AND token = %s AND expires_at > NOW()
                    """,
                    (user_id, token)
                )
                result = cur.fetchone()
        
        if not result:
            raise HTTPException(status_code=401, detail="Token jest nieważny lub został usunięty")

        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Nieprawidłowy token")
    
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token wygasł")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Niepoprawny token")
    
    if "id" not in payload or "login" not in payload or "email" not in payload:
        raise HTTPException(status_code=401, detail="Nieautoryzowany")
    
    user_id = payload["id"]
    token_str = token

    conn = get_connection()
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT user_id, token, expires_at 
                FROM users_token 
                WHERE user_id = %s AND token = %s AND expires_at > NOW()
                """,
                (user_id, token_str)
            )
            result = cur.fetchone()
    
    if not result:
        raise HTTPException(status_code=401, detail="Token jest nieważny lub został usunięty")
    
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
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE id != %s", (current_user,))
                users = cur.fetchall()  # list of dicts
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd pobierania użytkowników: {str(e)}")

@app.post("/register")
async def register_user(request: RegisterRequest):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                # Sprawdzenie czy login istnieje
                cur.execute("SELECT 1 FROM users WHERE login = %s", (request.login,))
                if cur.fetchone():
                    raise HTTPException(status_code=400, detail="Użytkownik o tym loginie już istnieje.")

                # Haszowanie hasła
                hashed_pw = bcrypt.hashpw(request.passwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                # Wstawianie nowego użytkownika
                cur.execute(
                    """
                    INSERT INTO users (fullname, login, password, email)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (request.fullname, request.login, hashed_pw, request.email)
                )
        return {"message": "Użytkownik zarejestrowany pomyślnie"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd podczas rejestracji użytkownika: {str(e)}")

@app.post("/login")
async def login(request: LoginRequest):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Pobranie użytkownika po loginie
                cur.execute("SELECT * FROM users WHERE login = %s", (request.login,))
                user_data = cur.fetchone()
                if not user_data:
                    raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")

                # Sprawdzenie hasła
                hashed = user_data["password"]
                if not bcrypt.checkpw(request.password.encode('utf-8'), hashed.encode('utf-8')):
                    raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")

                # Generowanie tokenu JWT
                payload = {
                    "id": user_data["id"],
                    "fullname": user_data["fullname"],
                    "login": user_data["login"],
                    "email": user_data["email"],
                    "exp": datetime.utcnow() + timedelta(hours=1)
                }
                token = jwt.encode(payload, KEY, algorithm="HS256")

                # Zapis tokenu do bazy
                cur.execute(
                    """
                    INSERT INTO users_token (user_id, issued_at, expires_at, token)
                    VALUES (%s, NOW(), NOW() + INTERVAL '1 hour', %s)
                    """,
                    (user_data["id"], token)
                )

        return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd logowania: {str(e)}")

@app.get("/welcomepage")
async def get_all_users(current_user: int = Depends(verify_token)):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Pobierz wszystkich użytkowników (id, fullname, email)
                cur.execute("SELECT id, fullname, email FROM users")
                users = cur.fetchall()

                # Pobierz user_id z tabeli users_token, żeby wiedzieć kto jest aktywny
                cur.execute("SELECT user_id FROM users_token")
                active_rows = cur.fetchall()
                active_ids = {row["user_id"] for row in active_rows}

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

@app.post("/upload_public_key")
async def upload_public_key(request: PublicKeyRequest, user = Depends(get_current_user)):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                # Sprawdź, czy istnieje klucz dla danego user_id
                cur.execute("SELECT id FROM encryption_keys WHERE user_id = %s", (user.id,))
                existing = cur.fetchone()

                if existing:
                    cur.execute(
                        "UPDATE encryption_keys SET public_key = %s, created_at = %s WHERE user_id = %s",
                        (request.public_key, datetime.utcnow(), user.id)
                    )
                else:
                    cur.execute(
                        "INSERT INTO encryption_keys (user_id, public_key, created_at) VALUES (%s, %s, %s)",
                        (user.id, request.public_key, datetime.utcnow())
                    )
        return {"message": f"Klucz publiczny dla użytkownika {user.fullname} został zapisany."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd zapisu klucza: {str(e)}")

@app.get("/has_public_key")
async def has_public_key(user: User = Depends(get_current_user)):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM encryption_keys WHERE user_id = %s", (user.id,))
                result = cur.fetchone()
                key_exists = result is not None
        return {"has_public_key": key_exists}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd sprawdzania klucza: {str(e)}")

@app.get("/get_user_token", response_model=LoginResponse)
def get_user_token(login: str = Query(...)):
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                # Pobierz ID użytkownika po loginie
                cur.execute("SELECT id FROM users WHERE login = %s", (login,))
                user = cur.fetchone()
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")

                user_id = user[0]

                # Pobierz najnowszy token
                cur.execute("""
                    SELECT token FROM users_token
                    WHERE user_id = %s
                    ORDER BY issued_at DESC
                    LIMIT 1
                """, (user_id,))
                token_row = cur.fetchone()

                if token_row:
                    return LoginResponse(access_token=token_row[0])
                else:
                    raise HTTPException(status_code=404, detail="Token not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/conversation")
def get_or_create_conversation(data: ConversationRequest, current_user: int = Depends(verify_token)):
    id_od = data.id_od
    id_do = data.id_do

    if id_od == id_do:
        raise HTTPException(status_code=400, detail="Nie można stworzyć konwersacji z samym sobą.")

    try:
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Sprawdź, czy konwersacja już istnieje (dwóch uczestników)
                cur.execute("""
                    SELECT cp1.conversation_id
                    FROM conversation_participants cp1
                    WHERE cp1.user_id IN (%s, %s)
                    GROUP BY cp1.conversation_id
                    HAVING COUNT(*) = 2 AND COUNT(DISTINCT cp1.user_id) = 2
                    LIMIT 1
                """, (id_od, id_do))

                result = cur.fetchone()
                if result:
                    return {"conversation_id": result["conversation_id"], "status": "existing"}

                # Stwórz nową konwersację
                cur.execute("""
                    INSERT INTO conversations (is_group, name, created_at)
                    VALUES (FALSE, NULL, %s)
                    RETURNING id
                """, (datetime.utcnow(),))

                new_conv_id = cur.fetchone()["id"]

                # Dodaj uczestników
                cur.execute("""
                    INSERT INTO conversation_participants (conversation_id, user_id, joined_at)
                    VALUES (%s, %s, %s),
                           (%s, %s, %s)
                """, (
                    new_conv_id, id_od, datetime.utcnow(),
                    new_conv_id, id_do, datetime.utcnow()
                ))

                return {"conversation_id": new_conv_id, "status": "created"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd serwera: {str(e)}")

@app.get("/get_messages/{user1_id}/{user2_id}", response_model=list[MessageResponse])
def get_conversation_messages(user1_id: int, user2_id: int, current_user: int = Depends(verify_token)):
    if current_user not in (user1_id, user2_id):
        raise HTTPException(status_code=403, detail="Nie jesteś uczestnikiem tej konwersacji.")

    try:
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Znajdź id konwersacji z dwoma użytkownikami
                cur.execute("""
                    SELECT c.id FROM conversations c
                    JOIN conversation_participants p1 ON c.id = p1.conversation_id AND p1.user_id = %s
                    JOIN conversation_participants p2 ON c.id = p2.conversation_id AND p2.user_id = %s
                    WHERE (SELECT COUNT(*) FROM conversation_participants WHERE conversation_id = c.id) = 2
                    LIMIT 1
                """, (user1_id, user2_id))

                conversation = cur.fetchone()
                if not conversation:
                    raise HTTPException(status_code=404, detail="Konwersacja nie istnieje.")

                conversation_id = conversation["id"]

                # Pobierz wiadomości i wybierz odpowiednie pole content w zależności od nadawcy
                cur.execute("""
                    SELECT
                        id,
                        conversation_id,
                        sender_id,
                        sent_at,
                        CASE
                            WHEN sender_id = %s THEN content_sender_encrypted
                            ELSE content
                        END AS content
                    FROM messages
                    WHERE conversation_id = %s
                    ORDER BY sent_at ASC
                """, (current_user, conversation_id))

                messages = cur.fetchall()
                return messages

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd serwera: {str(e)}")

@app.post("/send_message")
def send_message(request: MessageSendRequest):
    id_od = request.id_od
    id_do = request.id_do
    content = request.content
    content_sender_encrypted = request.content_sender_encrypted

    if id_od == id_do:
        raise HTTPException(status_code=400, detail="Nie można wysłać wiadomości do samego siebie.")

    try:
        conn = get_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Szukamy istniejącej konwersacji
                cur.execute("""
                    SELECT cp1.conversation_id
                    FROM conversation_participants cp1
                    JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
                    WHERE cp1.user_id = %s AND cp2.user_id = %s
                    LIMIT 1
                """, (id_od, id_do))

                conv = cur.fetchone()

                if conv:
                    conversation_id = conv["conversation_id"]
                else:
                    # Tworzymy nową konwersację
                    cur.execute("""
                        INSERT INTO conversations (is_group, name, created_at)
                        VALUES (FALSE, NULL, %s)
                        RETURNING id
                    """, (datetime.utcnow(),))
                    conversation_id = cur.fetchone()["id"]

                    # Dodajemy uczestników
                    cur.execute("""
                        INSERT INTO conversation_participants (conversation_id, user_id, joined_at)
                        VALUES (%s, %s, %s),
                               (%s, %s, %s)
                    """, (conversation_id, id_od, datetime.utcnow(), conversation_id, id_do, datetime.utcnow()))

                # Zapisujemy wiadomość z oboma szyfrowaniami
                cur.execute("""
                    INSERT INTO messages (conversation_id, sender_id, content, content_sender_encrypted, sent_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (conversation_id, id_od, content, content_sender_encrypted, datetime.utcnow()))

                # Commit nastąpi automatycznie po wyjściu z with conn

        return {
            "conversation_id": conversation_id,
            "sender_id": id_od,
            "content": content,
            "content_sender_encrypted": content_sender_encrypted,
            "sent_at": datetime.utcnow()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd serwera: {str(e)}")
    
#curl.exe -X POST http://localhost:8001/get_public_key -H "Content-Type: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZnVsbG5hbWUiOiJBZGFtIE1henVyZWsiLCJsb2dpbiI6ImFkYW0iLCJlbWFpbCI6ImFkYW1tYXp1cmVrODlAZ21haWwuY29tIiwiZXhwIjoxNzUyMDc4NTU2fQ.kQsGTRU2B7XGA4F9k_a01uiCMvXvhmexO_41sV_F7F4" -d '{\"user_id\": 2}'
@app.post("/get_public_key")
def get_public_key(data: PublicKeyRequestByUserid, current_user: int = Depends(verify_token)):
    user_id = data.user_id
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT public_key
                    FROM encryption_keys
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
                result = cur.fetchone()
                if not result:
                    raise HTTPException(status_code=404, detail="Publiczny klucz użytkownika nie został znaleziony.")
                return {"public_key": result["public_key"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Błąd serwera: {str(e)}")
