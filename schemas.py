# schemas.py
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR...",
                "token_type": "bearer"
            }
        }

class User(BaseModel):
    id: Optional[int] = None
    email: EmailStr  # Use EmailStr for better email validation
    is_active: bool
    role: str

    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str

class UserCreate(BaseModel):
    email: EmailStr  # Use EmailStr for better email validation
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long.")
    role: Optional[str] = Field(
        "user",
        pattern="^(admin|user|tester)$",
        description="Role must be 'admin', 'user', or 'tester'"
    )
    class Config:
        schema_extra = {
            "example": {
                "email": "new_user@example.com",
                "password": "strongpassword123",
                "role": "user"
            }
        }
