from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from ..database import get_db
from ..models import User_Product, User_Vendor, User_CWE, CVE, CVE_Product, Product, CVE_Vendor, Vendor, Alerts
from ..schemas import VulnerableProduct, SubscriptionCounts, VulnerableVendor
from typing import List
from datetime import datetime, timedelta, timezone
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a new router instance for dashboard statistics
router = APIRouter()

def calculate_time_range(time_range: str) -> datetime:
    """Parse user-friendly time range into a datetime filter."""
    now = datetime.now(timezone.utc)
    time_ranges = {
        "24h": timedelta(hours=24),
        "3d": timedelta(days=3),
        "1w": timedelta(weeks=1),
    }
    delta = time_ranges.get(time_range)
    if not delta:
        raise HTTPException(status_code=400, detail="Invalid time range. Use '24h', '3d', or '1w'.")
    return now - delta

# Endpoint for Number of Subscriptions
@router.get("/subscription-counts", response_model=SubscriptionCounts)
def get_subscription_counts(
    user_id: int = Query(..., description="The ID of the user to count subscriptions for"),
    db: Session = Depends(get_db)
):
    """Get subscription counts for products, vendors, and CWEs by user ID."""
    try:
        product_count = db.query(User_Product).filter(User_Product.user_id == user_id).count()
        vendor_count = db.query(User_Vendor).filter(User_Vendor.user_id == user_id).count()
        cwe_count = db.query(User_CWE).filter(User_CWE.user_id == user_id).count()
        total_count = product_count + vendor_count + cwe_count

        return {
            "products": product_count,
            "vendors": vendor_count,
            "cwes": cwe_count,
            "total": total_count
        }

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")

# Endpoint for Most Vulnerable Products
@router.get("/most-vulnerable-products", response_model=List[VulnerableProduct])
def get_most_vulnerable_products(
    time_range: str = Query(..., description="Time range: '24h', '3d', or '1w'"),
    db: Session = Depends(get_db)
):
    """Get the top 3 most vulnerable products based on CVE count within a time range."""
    try:
        time_filter = calculate_time_range(time_range)

        subquery = (
            db.query(CVE_Product.product_id, func.count(CVE.cve_id).label("cve_count"))
            .join(CVE, CVE_Product.cve_id == CVE.cve_id)
            .filter(CVE.updated_at >= time_filter)
            .group_by(CVE_Product.product_id)
            .subquery()
        )

        results = (
            db.query(Product.product_name, subquery.c.cve_count)
            .join(subquery, subquery.c.product_id == Product.product_id)
            .order_by(subquery.c.cve_count.desc())
            .limit(3)
            .all()
        )

        return [{"product_name": row.product_name, "cve_count": row.cve_count} for row in results]

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")

# Endpoint for Most Vulnerable Vendors
@router.get("/most-vulnerable-vendors", response_model=List[VulnerableVendor])
def get_most_vulnerable_vendors(
    time_range: str = Query(..., description="Time range: '24h', '3d', or '1w'"),
    db: Session = Depends(get_db)
):
    """Get the top 3 most vulnerable vendors based on CVE count within a time range."""
    try:
        time_filter = calculate_time_range(time_range)

        subquery = (
            db.query(CVE_Vendor.vendor_id, func.count(CVE.cve_id).label("cve_count"))
            .join(CVE, CVE_Vendor.cve_id == CVE.cve_id)
            .filter(CVE.updated_at >= time_filter)
            .group_by(CVE_Vendor.vendor_id)
            .subquery()
        )

        results = (
            db.query(Vendor.vendor_name, subquery.c.cve_count)
            .join(subquery, subquery.c.vendor_id == Vendor.vendor_id)
            .order_by(subquery.c.cve_count.desc())
            .limit(3)
            .all()
        )

        return [{"vendor_name": row.vendor_name, "cve_count": row.cve_count} for row in results]

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")

# Endpoint for Alerts Count
@router.get("/alerts-count", response_model=dict)
def get_alerts_count(db: Session = Depends(get_db)):
    """Get the count of new and treated CVEs in the alerts table."""
    try:
        is_table_empty = db.query(Alerts).count() == 0
        if is_table_empty:
            return {"message": "No data"}

        new_cves_count = db.query(Alerts).filter(Alerts.is_new_cve == True).count()
        updated_cves_count = db.query(Alerts).filter(Alerts.is_new_cve == False).count()

        return {
            "new_cves": new_cves_count,
            "updated_cves": updated_cves_count
        }

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")

# Endpoint for Number of Vulnerabilities per Product
@router.get("/vulnerabilities-per-product", response_model=List[VulnerableProduct])
def get_vulnerabilities_per_product(db: Session = Depends(get_db)):
    """Get the number of vulnerabilities per product."""
    try:
        result = (
            db.query(
                Product.product_name,
                func.count(CVE_Product.cve_id).label("vulnerability_count")
            )
            .join(CVE_Product, Product.product_id == CVE_Product.product_id)
            .group_by(Product.product_name)
            .order_by(func.count(CVE_Product.cve_id).desc())
            .all()
        )

        return [{"product_name": row[0], "vulnerability_count": row[1]} for row in result]

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")

# Endpoint for Most Occurring CVEs
@router.get("/most-occurring-cves", response_model=List[dict])
def get_most_occurring_cves(db: Session = Depends(get_db)):
    """Get the top 10 most occurring CVEs in the alerts table."""
    try:
        result = (
            db.query(
                Alerts.cve_id,
                func.count(Alerts.cve_id).label("occurrence_count")
            )
            .group_by(Alerts.cve_id)
            .order_by(func.count(Alerts.cve_id).desc())
            .limit(10)
            .all()
        )

        if not result:
            logger.info("No CVEs found in the alerts table.")
            return []

        detailed_result = []
        for row in result:
            cve_summary = (
                db.query(CVE.summary).filter(CVE.cve_id == row[0]).scalar()
            )
            detailed_result.append({
                "cve_id": row[0],
                "occurrence_count": row[1],
                "summary": cve_summary or "No summary available"
            })

        return detailed_result

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal server error.")
