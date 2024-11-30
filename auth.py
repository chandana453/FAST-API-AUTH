# auth.py
from typing import Optional, List

from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os

# SECRET_KEY = "Acm73bbFD5fLr4_yvTyRNiux-KpPOrlW5j1FYQ2WWCc"  # Replace with a secure, random secret key
SECRET_KEY = os.getenv("SECRET_KEY", "Acm73bbFD5fLr4_yvTyRNiux-KpPOrlW5j1FYQ2WWCc")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Adjust this value to increase/decrease hashing rounds
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def _create_token(data: dict, expires_delta: Optional[timedelta], role: Optional[str] = None,
                  scopes: Optional[List[str]] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})

    if role:
        to_encode.update({"role": role})
    if scopes:
        to_encode.update({"scopes": scopes})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, role: Optional[str] = None,
                        scopes: Optional[List[str]] = None) -> str:
    return _create_token(data, expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), role, scopes)


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None, role: Optional[str] = None,
                         scopes: Optional[List[str]] = None) -> str:
    return _create_token(data, expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), role, scopes)