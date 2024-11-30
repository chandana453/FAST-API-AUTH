from typing import List

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import jwt
from datetime import timedelta

from models import Base,User
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

from fastapi import FastAPI

# Import the logger from log_config.py
from log_config import logger
from jose import JWTError, ExpiredSignatureError



# Initialize FastAPI
app = FastAPI()

Base.metadata.create_all(bind=engine)
# @app.on_event("startup")
# async def startup_event():
#     try:
#         Base.metadata.create_all(bind=engine)
#         print("Startup event: Database initialized")
#     except Exception as e:
#         print(f"Error initializing the database: {e}")
#
# @app.on_event("shutdown")
# async def shutdown_event():
#     # Perform cleanup tasks
#     print("Shutdown event: Application shutting down")
# # Helper functions


# Create a sample user if it doesn't exist
def init_db():
    logger.info("went into initialize database")
    db = next(get_db())
    if not db.query(User).filter(User.email == "admin@gmail.com").first():
        user = User(email="admin@gmail.com", hashed_password=get_password_hash("admin"), role='admin')
        db.add(user)
        db.commit()
        db.close()
    # logger.info("Admin user created", extra={"email": user.email})

# Initialize the database with a default user
init_db()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", scopes={"user": "General user access", "admin": "Admin access"})

# Authorization Dependency
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        logger.info("Went into get_current_user")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            logger.error("Invalid credentials found for {}".format(email))
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = get_user(db, email)
        if user is None:
            logger.error("User not found for {}".format(email))
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except ExpiredSignatureError:
        logger.error("Token has expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError:
        logger.error("Invalid token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def role_required(required_roles: List[str]):
    def role_checker(user: User = Depends(get_current_user)):
        logger.info("Went into role_required and role_checker api")
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
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    return scope_checker

# Login endpoint
@app.post("/login", response_model=schemas.Token)
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
@app.get("/users/me", response_model=schemas.User)
async def read_users_me(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        logger.info("login user details function read_users_me")
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
@app.post("/users/", response_model=schemas.User)
def create_user(
        user: schemas.UserCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(role_required(['admin', 'user']))
):
    logger.info("Went into create user function for {} {}".format(user.email,user.role))
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
    logger.info("User successfully created with details {} {}".format(user.email,user.role))
    try:
        db.commit()
        db.refresh(db_user)
    except IntegrityError:
        db.rollback()
        logger.info("User with this email {} {} already exists".format(user.email,user.role))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    return db_user

# Protected endpoint example
@app.get("/admin-data/", response_model=schemas.User,dependencies=[Depends(role_required(["admin"])), Depends(scopes_required(["manage_users"]))])
def get_admin_data(current_user: User = Depends(role_required(['admin']))):
    # Only admin can access this endpoint
    return current_user

@app.get("/user-resource/", dependencies=[Depends(role_required(["user"])), Depends(scopes_required(["read_data", "edit_data"]))])
def get_user_resource():
    return {"message": "User resource with read and edit permissions"}

# Route that requires 'admin' role and 'manage_users' scope
@app.get("/admin-dashboard/", dependencies=[Depends(role_required(["admin"])), Depends(scopes_required(["manage_users"]))])
def admin_dashboard():
    return {"message": "Welcome to the admin dashboard"}

# Route that requires 'user' role and 'edit_data' scope
@app.get("/edit-data/", dependencies=[Depends(role_required(["user"])), Depends(scopes_required(["edit_data"]))])
def edit_data():
    return {"message": "You can edit the data"}



if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
