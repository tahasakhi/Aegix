from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from ..database import get_db
from ..models import CVE, Product, Vendor, CWE, CVE_URL, CVE_Product, CVE_Vendor, CVE_CWE, User_Vendor, User_Product, User_CWE
from ..schemas import CVEWithLinks  # Import the new Pydantic model

router = APIRouter()

# Helper function to filter CVEs based on a time range
def filter_cves_by_time(db: Session, time_filter: Optional[str] = None):
    now = datetime.now(timezone.utc)
    if time_filter == '24h':
        delta = timedelta(days=1)
    elif time_filter == '1w':
        delta = timedelta(weeks=1)
    elif time_filter == '1m':
        delta = timedelta(weeks=4)
    else:
        return db.query(CVE).order_by(CVE.updated_at.desc()).all()

    return db.query(CVE).filter(CVE.updated_at >= now - delta).order_by(CVE.updated_at.desc()).all()

# Fetch all CVEs with linked data (products, vendors, CWEs, URLs)
@router.get("/", response_model=List[CVEWithLinks])  # Updated response model
async def get_cves(
    db: Session = Depends(get_db), 
    time_filter: Optional[str] = None
):
    # Filter CVEs by time if a filter is provided
    cves = filter_cves_by_time(db, time_filter)

    result = []
    for cve in cves:
        # Query linked data for each CVE
        products = (
            db.query(Product)
            .join(CVE_Product)
            .filter(CVE_Product.cve_id == cve.cve_id)
            .all()
        )
        vendors = (
            db.query(Vendor)
            .join(CVE_Vendor)
            .filter(CVE_Vendor.cve_id == cve.cve_id)
            .all()
        )
        cwes = (
            db.query(CWE)
            .join(CVE_CWE)
            .filter(CVE_CWE.cve_id == cve.cve_id)
            .all()
        )
        urls = (
            db.query(CVE_URL)
            .filter(CVE_URL.cve_id == cve.cve_id)
            .all()
        )

        # Construct the CVE data in the format of the Pydantic model
        cve_data = CVEWithLinks(
            cve_id=cve.cve_id,
            summary=cve.summary,
            cvss2=cve.cvss2,
            cvss3=cve.cvss3,
            created_at=cve.created_at,
            updated_at=cve.updated_at,
            products=[product.product_name for product in products],
            vendors=[vendor.vendor_name for vendor in vendors],
            cwes=[cwe.cwe_id for cwe in cwes if cwe and cwe.cwe_id],  # Ensure non-null CWEs
            urls=[
                {"url": url.url, "content": url.content or None} for url in urls
            ],  # Ensure robust URL content
        )

        result.append(cve_data)

    return result

# Fetch CVEs based on user subscriptions to vendors
@router.get("/subscriptions/vendors", response_model=List[CVEWithLinks])  # Updated response model
async def get_cves_by_vendor_subscription(user_id: int, db: Session = Depends(get_db)):
    # Fetch vendor subscriptions for the user
    vendor_ids = db.query(User_Vendor).filter(User_Vendor.user_id == user_id).all()
    vendor_ids = [vendor.vendor_id for vendor in vendor_ids]

    cves = db.query(CVE).join(CVE_Vendor).filter(CVE_Vendor.vendor_id.in_(vendor_ids)).order_by(CVE.updated_at.desc()).all()
    return [CVEWithLinks.from_orm(cve) for cve in cves]

# Fetch CVEs based on user subscriptions to products
@router.get("/subscriptions/products", response_model=List[CVEWithLinks])  # Updated response model
async def get_cves_by_product_subscription(user_id: int, db: Session = Depends(get_db)):
    # Fetch product subscriptions for the user
    product_ids = db.query(User_Product).filter(User_Product.user_id == user_id).all()
    product_ids = [product.product_id for product in product_ids]

    cves = db.query(CVE).join(CVE_Product).filter(CVE_Product.product_id.in_(product_ids)).order_by(CVE.updated_at.desc()).all()
    return [CVEWithLinks.from_orm(cve) for cve in cves]

# Fetch CVEs based on user subscriptions to CWEs
@router.get("/subscriptions/cwes", response_model=List[CVEWithLinks])  # Updated response model
async def get_cves_by_cwe_subscription(user_id: int, db: Session = Depends(get_db)):
    # Fetch CWE subscriptions for the user
    cwe_ids = db.query(User_CWE).filter(User_CWE.user_id == user_id).all()
    cwe_ids = [cwe.cwe_id for cwe in cwe_ids]

    cves = db.query(CVE).join(CVE_CWE).filter(CVE_CWE.cwe_id.in_(cwe_ids)).order_by(CVE.updated_at.desc()).all()
    return [CVEWithLinks.from_orm(cve) for cve in cves]

# Fetch CVEs based on all user subscriptions (vendors, products, CWEs)
@router.get("/subscriptions", response_model=List[CVEWithLinks])  # Updated response model
async def get_cves_by_all_subscriptions(user_id: int, db: Session = Depends(get_db)):
    # Fetch vendor, product, and CWE subscriptions for the user
    vendor_ids = db.query(User_Vendor).filter(User_Vendor.user_id == user_id).all()
    product_ids = db.query(User_Product).filter(User_Product.user_id == user_id).all()
    cwe_ids = db.query(User_CWE).filter(User_CWE.user_id == user_id).all()
    
    vendor_ids = [vendor.vendor_id for vendor in vendor_ids]
    product_ids = [product.product_id for product in product_ids]
    cwe_ids = [cwe.cwe_id for cwe in cwe_ids]

    cves = db.query(CVE).join(CVE_Vendor).filter(CVE_Vendor.vendor_id.in_(vendor_ids)) \
        .join(CVE_Product).filter(CVE_Product.product_id.in_(product_ids)) \
        .join(CVE_CWE).filter(CVE_CWE.cwe_id.in_(cwe_ids)) \
        .order_by(CVE.updated_at.desc()).all()
    return [CVEWithLinks.from_orm(cve) for cve in cves]
