from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime


# Define the CVE URL schema
class CVEURL(BaseModel):
    url: str
    content: Optional[str] = None

    class Config:
        from_attributes = True  # Allows using SQLAlchemy objects directly

# Updated CVE schema with linked data
class CVEWithLinks(BaseModel):
    cve_id: str
    summary: Optional[str] = None
    cvss2: Optional[float] = None
    cvss3: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    products: List[str] = []  # Default empty list
    vendors: List[str] = []  # Default empty list
    cwes: List[str] = []  # Default empty list
    urls: List[Dict[str, Optional[str]]] = []  # Default empty list with flexible URL structure

    class Config:
        from_attributes = True



class VulnerableProduct(BaseModel):
    product_name: str
    cve_count: int

    class Config:
        schema_extra = {
            "example": {
                "product_name": "Product A",
                "cve_count": 12
            }
        }

class VulnerableVendor(BaseModel):
    vendor_name: str
    cve_count: int

    class Config:
        schema_extra = {
            "example": {
                "vendor_name": "Vendor X",
                "cve_count": 8
            }
        }

class SubscriptionCounts(BaseModel):
    products: int
    vendors: int
    cwes: int
    total: int

    class Config:
        schema_extra = {
            "example": {
                "products": 10,
                "vendors": 5,
                "cwes": 2,
                "total": 17
            }
        }
from pydantic import BaseModel

class AlertStats(BaseModel):
    new_cves_count: int
    treated_cves_count: int
class VulnerableProduct(BaseModel):
    product_name: str
    vulnerability_count: int

    class Config:
        schema_extra = {
            "example": {
                "product_name": "Example Product",
                "vulnerability_count": 25
            }
        }

class MostOccurringCVE(BaseModel):
    cve_id: str
    occurrence_count: int
    summary: str

    class Config:
        schema_extra = {
            "example": {
                "cve_id": "CVE-2024-1234",
                "occurrence_count": 25,
                "summary": "Buffer overflow in XYZ product..."
            }
        }


