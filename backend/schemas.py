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

