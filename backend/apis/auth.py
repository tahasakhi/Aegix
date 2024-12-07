import os
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

DATABASE_URL = os.environ['AEGIX_DATABASE_URL']  

# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Database Models
class PlanType(Base):
    __tablename__ = "plan_types"
    plan_id = Column(Integer, primary_key=True, index=True)
    plan_name = Column(String(50), nullable=False)
    plan_price = Column(Float, nullable=False)
    immediate_notification = Column(Boolean, default=False)
    max_users = Column(Integer, nullable=False)
    max_subscriptions = Column(Integer, nullable=False)

class Organization(Base):
    __tablename__ = "organizations"
    organization_id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    plan_type = Column(Integer, ForeignKey("plan_types.plan_id"))
    max_subscriptions = Column(Integer, nullable=True)
    immediate_notification = Column(Boolean, default=False)

class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    organization_id = Column(Integer, ForeignKey("organizations.organization_id"))
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)

# Initialize the database
Base.metadata.create_all(bind=engine)

# FastAPI Router
router = APIRouter()

# Pydantic Models
class RegisterOrganization(BaseModel):
    name: str
    username: str
    email: str
    password: str

class RegisterUser(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    organization_username: str

class ResetPassword(BaseModel):
    email: str
    organization_username: str
    new_password: str

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@router.post("/register/organization")
def register_organization(data: RegisterOrganization, plan_id: int, db: Session = Depends(get_db)):
    # Fetch the selected plan from the database
    plan = db.query(PlanType).filter_by(plan_id=plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    # Create a new organization with plan details
    organization = Organization(
        name=data.name,
        username=data.username,
        email=data.email,
        password=data.password,  # No encryption
        plan_type=plan_id,
        max_subscriptions=plan.max_subscriptions,
        immediate_notification=plan.immediate_notification
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)

    return {
        "message": "Organization registered successfully",
        "organization_id": organization.organization_id
    }

@router.post("/register/user")
def register_user(data: RegisterUser, db: Session = Depends(get_db)):
    # Find organization by username
    organization = db.query(Organization).filter_by(username=data.organization_username).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Create a new user
    user = User(
        first_name=data.first_name,
        last_name=data.last_name,
        email=data.email,
        password=data.password,  # No encryption
        organization_id=organization.organization_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User registered successfully",
        "user_id": user.user_id
    }

@router.post("/reset-password")
def reset_password(data: ResetPassword, db: Session = Depends(get_db)):
    # Find the organization by username
    organization = db.query(Organization).filter_by(username=data.organization_username).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Find the user by email and organization ID
    user = db.query(User).filter_by(email=data.email, organization_id=organization.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update the user's password
    user.password = data.new_password  # No encryption
    db.commit()

    return {"message": "Password reset successfully"}
