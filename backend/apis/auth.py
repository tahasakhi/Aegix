import os
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..models import *
from ..database import get_db 

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

class AuthCredentials(BaseModel):
    email: str
    password: str

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

# Authentication Route
@router.post("/authenticate")
def authenticate(credentials: AuthCredentials, db: Session = Depends(get_db)):
    # Check credentials in the Organization table
    organization = db.query(Organization).filter_by(email=credentials.email, password=credentials.password).first()
    if organization:
        return {"message": "You are logged in as organization", "organization_id": organization.organization_id}

    # Check credentials in the User table
    user = db.query(User).filter_by(email=credentials.email, password=credentials.password).first()
    if user:
        return {"message": "You are logged in as user", "user_id": user.user_id}

    # If no match found
    raise HTTPException(status_code=401, detail="Invalid email or password")

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
