from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..models import Product, Vendor, CWE, User_Vendor, User_Product, User_CWE
from pydantic import BaseModel
from typing import List
from ..database import get_db 

router = APIRouter()


#----------------------------------------------------------------Diapley vendors/products/cwes-------------------------------
# Modified function: Fetch vendors and the number of products each has
@router.get("/options/vendor_product_counts")
def get_vendor_product_counts(db: Session = Depends(get_db)):
    results = (
        db.query(Vendor.vendor_id, Vendor.vendor_name, func.count(Product.product_id).label("product_count"))
        .join(Product, Product.vendor_id == Vendor.vendor_id, isouter=True)
        .group_by(Vendor.vendor_id, Vendor.vendor_name)
        .all()
    )

    # Format the response
    vendor_data = [
        {"vendor_id": vendor_id, "vendor_name": vendor_name, "product_count": product_count}
        for vendor_id, vendor_name, product_count in results
    ]

    return {"vendors": vendor_data}

# New function: Fetch all products with their vendor name
@router.get("/options/products_with_vendors")
def get_products_with_vendors(db: Session = Depends(get_db)):
    results = (
        db.query(Product.product_id, Product.product_name, Vendor.vendor_name)
        .join(Vendor, Product.vendor_id == Vendor.vendor_id)
        .all()
    )

    # Format the response
    product_data = [
        {"product_id": product_id, "product_name": product_name, "vendor_name": vendor_name}
        for product_id, product_name, vendor_name in results
    ]

    return {"products": product_data}

# find all CWEs
@router.get("/options/cwes")
def find_cwes(db: Session = Depends(get_db)):
    cwes = db.query(CWE).all()
    return {
        "cwes": [{"CWE ID": cwe.cwe_id, "name": cwe.name, "CWE url": cwe.cwe_url} for cwe in cwes]
    }



#---------------------------------------------------------Find subscriptions-------------------------------------------

# find vendor subscriptions for a user
@router.get("/subscriptions/vendor/{user_id}/")
def find_vendor_subscriptions(user_id: int, db: Session = Depends(get_db)):
    subscribed_vendors = (
        db.query(Vendor.vendor_name)
        .join(User_Vendor, Vendor.vendor_id == User_Vendor.vendor_id)
        .filter(User_Vendor.user_id == user_id)
        .all()
    )
    return {
        "vendors": [vendor.vendor_name for vendor in subscribed_vendors],
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


# Find CWE subscriptions for a user
@router.get("/subscriptions/cwes/{user_id}/")
def find_cwe_subscriptions(user_id: int, db: Session = Depends(get_db)):
    # Query for CWE ID and name
    subscribed_cwes = (
        db.query(CWE.cwe_id, CWE.name)
        .join(User_CWE, CWE.cwe_id == User_CWE.cwe_id)
        .filter(User_CWE.user_id == user_id)
        .all()
    )
    # Return both cwe_id and name
    return {
        "cwes": [{"cwe_id": cwe.cwe_id, "name": cwe.name} for cwe in subscribed_cwes],
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
        vendor = db.query(Vendor).filter(Vendor.vendor_name == vendor_name).first()
        if vendor and vendor.vendor_id not in existing_vendor_ids:
            new_vendors.append(User_Vendor(user_id=user_id, vendor_id=vendor.vendor_id))
    db.bulk_save_objects(new_vendors)
    db.commit()
    return {"message": "Subscriptions updated successfully!"}


# Unsubscribe to a vendor
@router.post("/unsubscribe_to/vendor/{user_id}")
def unsubscribe_vendor(user_id: int, vendors: list[str], db: Session = Depends(get_db)):
    for vendor_name in vendors:
        vendor = db.query(Vendor).filter(Vendor.vendor_name == vendor_name).first()
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
    for cwe_id in cwes:
        cwe = db.query(CWE).filter(CWE.cwe_id == cwe_id).first()
        if cwe and cwe.cwe_id not in existing_cwe_ids:
            new_cwes.append(User_CWE(user_id=user_id, cwe_id=cwe.cwe_id))
    db.bulk_save_objects(new_cwes)
    db.commit()
    return {"message": "Subscriptions updated successfully!"}


# Unsubscribe to CWEs
@router.post("/unsubscribe_to/cwe/{user_id}")
def unsubscribe_cwe(user_id: int, cwes: list[str], db: Session = Depends(get_db)):
    for cwe_id in cwes:
        cwe = db.query(CWE).filter(CWE.cwe_id == cwe_id).first()
        if cwe:
            db.query(User_CWE).filter(
                User_CWE.user_id == user_id,
                User_CWE.cwe_id == cwe.cwe_id
            ).delete()
    db.commit()
    return {"message": "Unsubscribed successfully!"}
