# models.py
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy import DateTime
from sqlalchemy.ext.declarative import as_declarative
from sqlalchemy import Enum
from enum import Enum as PyEnum

Base = declarative_base()


@as_declarative()
class Base:
 id = Column(Integer, primary_key=True, index=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True,nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(String, default='user')  # Add a role column
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class RoleEnum(PyEnum):
     admin = "admin"
     user = "user"
     tester = "tester"

role = Column(Enum(RoleEnum), default=RoleEnum.user)

def __repr__(self):
    return f"<User(id={self.id}, email='{self.email}', role='{self.role.name}', is_active={self.is_active})>"