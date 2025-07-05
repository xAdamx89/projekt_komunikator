from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    fullname: str
    login: str
    passwd: str
    email: EmailStr

class LoginRequest(BaseModel):
    login: str
    password: str