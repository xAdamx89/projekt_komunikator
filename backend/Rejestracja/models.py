from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class RegisterRequest(BaseModel):
    fullname: str
    login: str
    passwd: str
    email: EmailStr

class LoginRequest(BaseModel):
    login: str
    password: str
    
class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class PublicKeyRequest(BaseModel):
    public_key: str
    
class User(BaseModel):
    id: int
    login: str
    fullname: Optional[str] = None
    email: str
    
class ConversationRequest(BaseModel):
    id_od: int
    id_do: int
    
class MessageResponse(BaseModel):
    id: int
    conversation_id: int
    sender_id: int | None
    content: str
    sent_at: datetime
    
class MessageSendRequest(BaseModel):
    id_od: int
    id_do: int
    content: str  # zaszyfrowane dla odbiorcy
    content_sender_encrypted: str  # zaszyfrowane dla nadawcy
    
class PublicKeyRequest(BaseModel):
    public_key: str
    
class PublicKeyRequestByUserid(BaseModel):
    user_id: int