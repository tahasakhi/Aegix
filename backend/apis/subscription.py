from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models import Vendor, Product, User_Vendor, User_Product
from pydantic import BaseModel
from typing import List

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class SubscriptionUpdateRequest(BaseModel):
    user_id: int
    vendors: List[str]  
    products: List[str]  


# extract all vendors and products
@router.get("/options/")
def fetch_options(db: Session = Depends(get_db)):
    vendors = db.query(Vendor.vendor_name).all()
    products = db.query(Product.product_name).all()
    return {
        "vendors": [vendor[0] for vendor in vendors],
        "products": [product[0] for product in products],
    }


@router.get("/subscriptions/{user_id}/")
def fetch_subscriptions(user_id: int, db: Session = Depends(get_db)):
    # look for subscribed vendors
    subscribed_vendors = (
        db.query(Vendor.vendor_name)
        .join(User_Vendor, Vendor.vendor_id == User_Vendor.vendor_id)
        .filter(User_Vendor.user_id == user_id)
        .all()
    )
    # look for subscribed products
    subscribed_products = (
        db.query(Product.product_name)
        .join(User_Product, Product.product_id == User_Product.product_id)
        .filter(User_Product.user_id == user_id)
        .all()
    )

    return {
        "vendors": [vendor[0] for vendor in subscribed_vendors],
        "products": [product[0] for product in subscribed_products],
    }


@router.post("/subscriptions/")
def save_subscriptions(data: SubscriptionUpdateRequest, db: Session = Depends(get_db)):
    # Fetch the user's existing vendor subscriptions
    existing_vendor_subscriptions = (
        db.query(User_Vendor.vendor_id)
        .filter(User_Vendor.user_id == data.user_id)
        .all()
    )
    existing_vendor_ids = {vendor[0] for vendor in existing_vendor_subscriptions}
    # Fetch the user's existing product subscriptions
    existing_product_subscriptions = (
        db.query(User_Product.product_id)
        .filter(User_Product.user_id == data.user_id)
        .all()
    )
    existing_product_ids = {product[0] for product in existing_product_subscriptions}

    for vendor_name in data.vendors:
        vendor = db.query(Vendor).filter(Vendor.vendor_name == vendor_name).first()
        if vendor and vendor.vendor_id not in existing_vendor_ids:
            # Add new vendor subscription
            user_vendor = User_Vendor(user_id=data.user_id, vendor_id=vendor.vendor_id)
            db.add(user_vendor)

    for vendor_id in existing_vendor_ids:
        vendor_name = db.query(Vendor.vendor_name).filter(Vendor.vendor_id == vendor_id).scalar()
        if vendor_name not in data.vendors:
            # Remove vendor subscription if not in the new list
            db.query(User_Vendor).filter(
                User_Vendor.user_id == data.user_id,
                User_Vendor.vendor_id == vendor_id
            ).delete()

    for product_name in data.products:
        product = db.query(Product).filter(Product.product_name == product_name).first()
        if product and product.product_id not in existing_product_ids:
            # Add new product subscription
            user_product = User_Product(user_id=data.user_id, product_id=product.product_id)
            db.add(user_product)

    for product_id in existing_product_ids:
        product_name = db.query(Product.product_name).filter(Product.product_id == product_id).scalar()
        if product_name not in data.products:
            # Remove product subscription if not in the new list
            db.query(User_Product).filter(
                User_Product.user_id == data.user_id,
                User_Product.product_id == product_id
            ).delete()

    db.commit()
    return {"message": "Subscriptions updated successfully!"}

