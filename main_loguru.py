import json
from typing import List
import sys
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import jwt
from datetime import timedelta
from models import Base, User
from services import get_user, authenticate_user, user_exists
from database import engine, get_db
from auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
import schemas

# Import the logger from log_config.py
from loguru_config import logger,setup_logger
from jose import JWTError, ExpiredSignatureError
import redis.asyncio as redis


setup_logger()

# Initialize FastAPI
app = FastAPI()
v1_router = APIRouter()
v2_router = APIRouter()

Base.metadata.create_all(bind=engine)

# Create Redis client
redis_client = redis.from_url("redis://localhost:6379")

# Helper functions

# Create a sample user if it doesn't exist
def init_db():
    logger.info("Initializing database")
    db = next(get_db())
    if not db.query(User).filter(User.email == "admin@gmail.com").first():
        user = User(email="admin@gmail.com",
                    hashed_password=get_password_hash("admin"),
                    role='admin')
        db.add(user)
        db.commit()
        logger.info("Admin user created", extra={"email": user.email})
    db.close()

# Initialize the database with a default user
init_db()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v2/login", scopes={"user": "General user access", "admin": "Admin access"})

# Function to clear cache for a specific token
async def clear_cache(token: str):
    await redis_client.delete(f"user:{token}")
    logger.info(f"Cache cleared for token: {token}")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        logger.info("Retrieving current user")

        # Check Redis cache first
        user_data = await redis_client.get(f"user:{token}")
        if user_data:
            logger.warning("Fetched from redis cache data")
            user_data = json.loads(user_data)
            user = User(
                id=user_data["id"],
                email=user_data["email"],
                is_active=user_data["is_active"],
                role=user_data["role"],
                created_at=user_data["created_at"],
                updated_at=user_data["updated_at"]
            )
            return user

        # Decode token and fetch user from DB if not cached
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            await clear_cache(token)  # Clear cache in case of invalid credentials
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user = get_user(db, email)
        if user is None:
            await clear_cache(token)  # Clear cache if user is not found
            raise HTTPException(status_code=401, detail="User not found")

        # Cache user data in Redis
        user_dict = {
            "id": user.id,
            "email": user.email,
            "is_active": user.is_active,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        }
        await redis_client.set(f"user:{token}", json.dumps(user_dict), ex=600)  # Cache for 10 minutes
        logger.info(f"User data cached for token: {token}")
        return user
    except ExpiredSignatureError:
        await clear_cache(token)  # Clear cache if the token is expired
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError:
        await clear_cache(token)  # Clear cache for general JWT errors
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


def role_required(required_roles: List[str]):
    def role_checker(user: User = Depends(get_current_user)):
        logger.info("Checking user role")
        if user.role not in required_roles:
            logger.error("Access forbidden: insufficient rights")
            raise HTTPException(status_code=403, detail="Access forbidden: insufficient rights")
        return user
    return role_checker

def scopes_required(required_scopes: list):
    def scope_checker(token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            token_scopes = payload.get("scopes", [])
            if not set(required_scopes).issubset(token_scopes):
                logger.error("Insufficient permissions")
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return payload
        except JWTError:
            logger.error("Invalid token")
            raise HTTPException(status_code=401, detail="Invalid token")
    return scope_checker


@v1_router.post("/login", response_model=schemas.Token)
async def v1_login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=30))
    refresh_token = create_refresh_token(data={"sub": user.email})

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@v2_router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    logger.info("Login attempt", extra={"username": form_data.username})

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.error("Incorrect username or password", extra={"username": form_data.username})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Define role and scopes based on the user
    role = user.role
    if role == "admin":
        scopes = ["manage_users", "edit_data", "view_data"]
    elif role == "user":
        scopes = ["view_data", "edit_data"]
    else:
        scopes = ["view_data"]

    # Create access token with role and scopes
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires,
        role=role,
        scopes=scopes
    )

    # Create refresh token with role and scopes
    refresh_token = create_refresh_token(
        data={"sub": user.email},
        role=role,
        scopes=scopes
    )

    logger.info("Login API completed for user {}".format(form_data.username))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

# Get current user endpoint
@v2_router.get("/users/me", response_model=schemas.User)
async def read_users_me(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        logger.info("Fetching current user details")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            logger.error("Invalid credentials for {}".format(email))
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = get_user(db, email)
        if user is None:
            logger.error("User not found for details {}".format(email))
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        logger.error("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

# User creation endpoint
@v2_router.post("/users/", response_model=schemas.User)
def create_user(
        user: schemas.UserCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(role_required(['admin', 'user']))
):
    logger.info("Creating user with email {}".format(user.email))
    # Admin can create users with role 'user' and 'tester'
    if current_user.role == 'admin':
        if user.role not in ['user', 'tester']:
            logger.error("Admin can only create users with role 'user' or 'tester'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admin can only create users with role 'user' or 'tester'"
            )

    # User can only create users with role 'tester'
    elif current_user.role == 'user':
        if user.role != 'tester':
            logger.error("Users can only create users with role 'tester'")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Users can only create users with role 'tester'"
            )

    hashed_password = get_password_hash(user.password)

    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )

    db.add(db_user)
    logger.info("User successfully created with email {}".format(user.email))
    try:
        db.commit()
        db.refresh(db_user)
    except IntegrityError:
        db.rollback()
        logger.error("User with this email {} already exists".format(user.email))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    return db_user

# Protected endpoint example
@v2_router.get("/admin-data/", response_model=schemas.User, dependencies=[Depends(role_required(["admin"])), Depends(scopes_required(["manage_users"]))])
def get_admin_data(current_user: User = Depends(role_required(['admin']))):
    logger.info("Accessing admin data for user {}".format(current_user.email))
    # Only admin can access this endpoint
    return current_user

@v2_router.get("/user-resource/", dependencies=[Depends(role_required(["user"])), Depends(scopes_required(["read_data", "edit_data"]))])
def get_user_resource():
    logger.info("Accessing user resource")
    return {"message": "User resource with read and edit permissions"}

# Route that requires 'admin' role and 'manage_users' scope
@v2_router.get("/admin-resource/", dependencies=[Depends(role_required(["admin"])), Depends(scopes_required(["manage_users"]))])
def get_admin_resource(current_user: User = Depends(role_required(['admin']))):
    logger.info("Accessing admin resource for user {}".format(current_user.email))
    return {"message": "Admin resource accessed successfully"}

# Add the routers to the FastAPI app
app.include_router(v1_router, prefix="/v1", tags=["v1"])
app.include_router(v2_router, prefix="/v2", tags=["v2"])


if __name__ == "__main__":
    logger.info("Starting the FastAPI application")
    uvicorn.run(app, host="127.0.0.1", port=8080)
