from sqlalchemy.orm import Session
from models import User
from auth import verify_password
from log_config import logger

def get_user(db: Session, email: str):
    logger.info("Fetch the user details", extra={"email": email})
    return db.query(User).filter(User.email == email).first()

def user_exists(db: Session, email: str) -> bool:
    logger.info("Checking if user exists", extra={"email": email})
    return db.query(User).filter(User.email == email).count() > 0

def authenticate_user(db: Session, email: str, password: str):
    logger.info("Authenticating user", extra={"email": email})

    if not user_exists(db, email):
        logger.error("User not found", extra={"email": email})
        return False

    user = get_user(db, email)
    if not user:
        return False

    if not verify_password(password, user.hashed_password):
        logger.error("Incorrect password", extra={"email": email})
        return False
    return user
