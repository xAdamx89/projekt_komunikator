from pydantic import BaseModel, EmailStr
from typing import Optional

class RegisterRequest(BaseModel):
    fullname: str
    login: str
    passwd: str
    email: EmailStr

class LoginRequest(BaseModel):
    login: str
    password: str

class PublicKeyRequest(BaseModel):
    public_key: str
    
class User(BaseModel):
    id: int
    login: str
    fullname: Optional[str] = None