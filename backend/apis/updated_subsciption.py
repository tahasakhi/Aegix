from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Vendor, Product, User_Vendor, User_Product, CWE, User_CWE
from pydantic import BaseModel
from typing import List


router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


#----------------------------------------------------------------Diapley vendors/products/cwes-------------------------------

# find vendors and their products
@router.get("/options/prod_vend")
def find_prod_vend(db: Session = Depends(get_db)):
    vendors = db.query(Vendor).all()
    vendor_data = []
    for vendor in vendors:
        products = db.query(Product).filter(Product.vendor_id == vendor.vendor_id).all()
        vendor_data.append({
            "vendor": vendor.vend_name,
            "products": [product.product_name for product in products],
        })
    return {"vendors_and_products": vendor_data}


# find all CWEs
@router.get("/options/cwes")
def find_cwes(db: Session = Depends(get_db)):
    cwes = db.query(CWE).all()
    return {
        "cwes": [{"name": cwe.name, "description": cwe.description} for cwe in cwes]
    }



#---------------------------------------------------------Find subscriptions-------------------------------------------

# find vendor subscriptions for a user
@router.get("/subscriptions/vendor/{user_id}/")
def find_vendor_subscriptions(user_id: int, db: Session = Depends(get_db)):
    subscribed_vendors = (
        db.query(Vendor.vend_name)
        .join(User_Vendor, Vendor.vendor_id == User_Vendor.vendor_id)
        .filter(User_Vendor.user_id == user_id)
        .all()
    )
    return {
        "vendors": [vendor.vend_name for vendor in subscribed_vendors],
    }


# find product subscriptions for a user
@router.get("/subscriptions/product/{user_id}/")
def find_product_subscriptions(user_id: int, db: Session = Depends(get_db)):
    subscribed_products = (
        db.query(Product.product_name)
        .join(User_Product, Product.product_id == User_Product.product_id)
        .filter(User_Product.user_id == user_id)
        .all()
    )
    return {
        "products": [product.product_name for product in subscribed_products],
    }


# find CWE subscriptions for a user
@router.get("/subscriptions/cwes/{user_id}/")
def find_cwe_subscriptions(user_id: int, db: Session = Depends(get_db)):
    subscribed_cwes = (
        db.query(CWE.name)
        .join(User_CWE, CWE.id == User_CWE.cwe_id)
        .filter(User_CWE.user_id == user_id)
        .all()
    )
    return {
        "cwes": [cwe.name for cwe in subscribed_cwes],
    }





#------------------------------------SUBSCRIBE/UNSUBSCRIBE--------------------------------------------------

# Subscribe to a vendor
@router.post("/subscribe_to/vendor/{user_id}")
def subscribe_vendor(user_id: int, vendors: list[str], db: Session = Depends(get_db)):
    existing_vendor_ids = {
        vendor.vendor_id for vendor in db.query(User_Vendor).filter(User_Vendor.user_id == user_id).all()
    }
    new_vendors = []
    for vendor_name in vendors:
        vendor = db.query(Vendor).filter(Vendor.vend_name == vendor_name).first()
        if vendor and vendor.vendor_id not in existing_vendor_ids:
            new_vendors.append(User_Vendor(user_id=user_id, vendor_id=vendor.vendor_id))
    db.bulk_save_objects(new_vendors)
    db.commit()
    return {"message": "Subscriptions updated successfully!"}


# Unsubscribe to a vendor
@router.post("/unsubscribe_to/vendor/{user_id}")
def unsubscribe_vendor(user_id: int, vendors: list[str], db: Session = Depends(get_db)):
    for vendor_name in vendors:
        vendor = db.query(Vendor).filter(Vendor.vend_name == vendor_name).first()
        if vendor:
            db.query(User_Vendor).filter(
                User_Vendor.user_id == user_id,
                User_Vendor.vendor_id == vendor.vendor_id
            ).delete()

    db.commit()
    return {"message": "Unsubscribed successfully!"}


# Subscribe to a product
@router.post("/subscribe_to/product/{user_id}")
def subscribe_product(user_id: int, products: list[str], db: Session = Depends(get_db)):
    existing_product_ids = {
        product.product_id for product in db.query(User_Product).filter(User_Product.user_id == user_id).all()
    }
    new_products = []
    for product_name in products:
        product = db.query(Product).filter(Product.product_name == product_name).first()
        if product and product.product_id not in existing_product_ids:
            new_products.append(User_Product(user_id=user_id, product_id=product.product_id))
    db.bulk_save_objects(new_products)
    db.commit()
    return {"message": "Subscriptions updated successfully!"}


# Unsubscribe to a product
@router.post("/unsubscribe_to/product/{user_id}")
def unsubscribe_product(user_id: int, products: list[str], db: Session = Depends(get_db)):
    for product_name in products:
        product = db.query(Product).filter(Product.product_name == product_name).first()
        if product:
            db.query(User_Product).filter(
                User_Product.user_id == user_id,
                User_Product.product_id == product.product_id
            ).delete()
    db.commit()
    return {"message": "Unsubscribed successfully!"}


# Subscribe to CWEs
@router.post("/subscribe_to/cwe/{user_id}")
def subscribe_cwe(user_id: int, cwes: list[str], db: Session = Depends(get_db)):
    existing_cwe_ids = {
        cwe.cwe_id for cwe in db.query(User_CWE).filter(User_CWE.user_id == user_id).all()
    }
    new_cwes = []
    for cwe_name in cwes:
        cwe = db.query(CWE).filter(CWE.name == cwe_name).first()
        if cwe and cwe.id not in existing_cwe_ids:
            new_cwes.append(User_CWE(user_id=user_id, cwe_id=cwe.id))
    db.bulk_save_objects(new_cwes)
    db.commit()
    return {"message": "Subscriptions updated successfully!"}


# Unsubscribe to CWEs
@router.post("/unsubscribe_to/cwe/{user_id}")
def unsubscribe_cwe(user_id: int, cwes: list[str], db: Session = Depends(get_db)):
    for cwe_name in cwes:
        cwe = db.query(CWE).filter(CWE.name == cwe_name).first()
        if cwe:
            db.query(User_CWE).filter(
                User_CWE.user_id == user_id,
                User_CWE.cwe_id == cwe.id
            ).delete()
    db.commit()
    return {"message": "Unsubscribed successfully!"}
