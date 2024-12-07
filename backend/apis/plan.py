from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import Text
from ..database import SessionLocal
from ..models import PlanType, Organization, User
from pydantic import BaseModel
from typing import List

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class PackageChoice(BaseModel):
    user_id: int
    plan_id: int


@router.get('/plan/')
def show_package(db: Session = Depends(get_db)):
    plans = db.query(PlanType).all()
    return {
        "plans": [
            {
                "Plan": plan.plan_name,
                "Price": plan.plan_price,
                "Max Number of users": plan.max_users,
                "Max Number of Vendor/Product/CWE subscriptions": plan.max_subscriptions,
                "Notification Frequency": "daily" if plan.immediate_notification else "immediate",
            }
            for plan in plans
        ]
    }


@router.post('/plan/choose/')
def choose_package(package_choice: PackageChoice, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == package_choice.user_id).first()
    organization = db.query(Organization).filter(Organization.organization_id == user.organization_id).first()
    plan = db.query(PlanType).filter(PlanType.plan_id == package_choice.plan_id).first()
    organization.plan_type = package_choice.plan_id
    db.commit()
    return {"message": f"Plan {plan.plan_name} has been assigned to the organization."}


@router.get('/plan/{user_id}/current/')
def check_current_plan(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    organization = db.query(Organization).filter(Organization.organization_id == user.organization_id).first()

    current_plan = db.query(PlanType).filter(PlanType.plan_id == organization.plan_type).first()
    return {
        "Plan": current_plan.plan_name,
        "Price": current_plan.plan_price,
        "Max Number of users": current_plan.max_users,
        "Max Number of Vendor/Product/CWE subscriptions": current_plan.max_subscriptions,
        "Notification Frequency": current_plan.immediate_notification,
    }


@router.put('/plan/modify/{user_id}/')
def modify_package(user_id: int, plan_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    organization = db.query(Organization).filter(Organization.organization_id == user.organization_id).first()

    current_plan = db.query(PlanType).filter(PlanType.plan_id == organization.plan_type).first()

    if current_plan and current_plan.plan_id == plan_id:
        return {"message": "The selected plan is already the current plan."}

    organization.plan_type = plan_id
    db.commit()
    return {"message": f"Plan has been modified successfully."}
