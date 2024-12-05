import os
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any
from sqlalchemy import create_engine, Column, String, Text, DateTime, Float, Integer, func, MetaData, JSON, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base

# Database connection strings (replace with actual URLs)
OPENCVE_DATABASE_URL = os.environ['OPENCVE_DATABASE_URL']
AEGIX_DATABASE_URL = os.environ['AEGIX_DATABASE_URL']

# Separate metadata for each database
opencve_metadata = MetaData()
aegix_metadata = MetaData()

# Define models for OpenCVE database
BaseOpenCve = declarative_base(metadata=opencve_metadata)

class OpenCve(BaseOpenCve):
    __tablename__ = 'cves'
    id = Column(String, primary_key=True)
    cve_id = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    summary = Column(String, nullable=False)
    vendors = Column(Text)  # Add this line
    cvss2 = Column(Float)
    cvss3 = Column(Float)
    json = Column(JSON)  # Add this line
    cwes = Column(JSON)  # Add CWEs as JSONB

# Define models for Aegix database
BaseAegix = declarative_base(metadata=aegix_metadata)

class AegixCve(BaseAegix):
    __tablename__ = 'cves'
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    summary = Column(Text)
    cvss2 = Column(Float)
    cvss3 = Column(Float)

class Vendor(BaseAegix):
    __tablename__ = 'vendors'
    vend_id = Column(Integer, primary_key=True)
    vend_name = Column(String, unique=True, nullable=False)

class Product(BaseAegix):
    __tablename__ = 'products'
    prod_id = Column(Integer, primary_key=True)
    prod_name = Column(String, nullable=False)
    vend_id = Column(Integer)

class CveVendor(BaseAegix):
    __tablename__ = 'cves_vendors'
    cve_id = Column(Integer, primary_key=True)
    vend_id = Column(Integer, primary_key=True)
    is_predicted = Column(Boolean, default=False)

class CveProduct(BaseAegix):
    __tablename__ = 'cves_products'
    cve_id = Column(Integer, primary_key=True)
    prod_id = Column(Integer, primary_key=True)
    is_predicted = Column(Boolean, default=False)

class CveCwe(BaseAegix):
    __tablename__ = 'cves_cwes'
    cve_id = Column(Integer, primary_key=True)
    cwe_id = Column(Integer, primary_key=True)

class CveUrl(BaseAegix):
    __tablename__ = 'cves_urls'
    cve_id = Column(Integer, primary_key=True)
    url = Column(String, primary_key=True)

class Alerts(BaseAegix):
    __tablename__ = 'alerts'
    alert_id = Column(Integer, primary_key=True)
    cve_id = Column(Integer)
    is_new_cve = Column(Boolean, default=False)
    treated = Column(Boolean, default=False)

# Create database engines
print("[INFO] Creating database engines...")
opencve_engine = create_engine(OPENCVE_DATABASE_URL)
aegix_engine = create_engine(AEGIX_DATABASE_URL)

# Create sessions
print("[INFO] Creating database sessions...")
OpencveSession = sessionmaker(bind=opencve_engine)
AegixSession = sessionmaker(bind=aegix_engine)


# Global variable to keep track of the last printed CVE
last_printed_cve = None

def parse_vendors_products(vendors_list):
    print("[DEBUG] Parsing vendors and products...")
    vendors = set()
    products = []

    for item in vendors_list:
        if "$PRODUCT$" in item:
            vendor, product = item.split("$PRODUCT$")
            vendor = vendor.strip()
            product = product.strip()
            products.append(f"{product} ($PRODUCT$ {vendor})")  # Adjusted the format for consistency
            vendors.add(vendor)
        else:
            vendor = item.strip()
            vendors.add(vendor)
            
    print(f"[DEBUG] Vendors: {sorted(vendors)}")
    print(f"[DEBUG] Products: {products}")
    return sorted(vendors), products

def parse_cwes(cwes_json: Dict[str, Any]) -> list:
    try:
        return [cwe for cwe in cwes_json] if cwes_json else []
    except Exception as e:
        print(f"An error occurred while extracting CWEs: {e}")
        return []

def extract_urls(cve_json: Dict[str, Any]) -> list:
    try:
        # Extract URLs from the 'references' field in the JSON
        references = cve_json.get("references", [])
        urls = [ref.get("url") for ref in references if "url" in ref]
        return urls
    except Exception as e:
        print(f"An error occurred while extracting URLs: {e}")
        return []

def get_cve_data_from_opencve():
    global last_printed_cve
    print("[INFO] Fetching CVE data from OpenCVE...")
    session = OpencveSession()
    
    # Determine the time range for the query
    if last_printed_cve is None:
        # On the first run, retrieve CVEs from the last 2 days
        time_threshold = datetime.now() - timedelta(days=2)
    else:
        time_threshold = last_printed_cve
    
    print(f"[INFO] Querying for vulnerabilities published after {time_threshold}...")

    # Initialize cve_data as an empty list
    cve_data = []

    # Query for new or updated vulnerabilities since the last printed CVE or within the last 2 hours
    cves_query = session.query(OpenCve)\
        .filter(func.greatest(OpenCve.created_at, OpenCve.updated_at) > time_threshold)\
        .order_by(func.greatest(OpenCve.created_at, OpenCve.updated_at).desc()).all()

    if not cves_query:
        print("[INFO] No new vulnerabilities found.")
    else:
        for cve in cves_query:
            # Handle vendors column
            if cve.vendors:
                try:
                    vendors_list = json.loads(cve.vendors) if isinstance(cve.vendors, str) else cve.vendors
                    vendors, products = parse_vendors_products(vendors_list)
                except json.JSONDecodeError:
                    print("[ERROR] Vendors format is not as expected.")
                    vendors, products = (["N/A"], [])
            else:
                vendors, products = (["N/A"], [])

            # Extract URLs from JSON column
            urls = extract_urls(cve.json) if cve.json else []
            cwes = parse_cwes(cve.cwes) if cve.cwes else []

            data = {
                'id': cve.id,
                'cve_id': cve.cve_id,
                'created_at': cve.created_at,
                'updated_at': cve.updated_at,
                'vendors': vendors,
                'products': products,
                'summary': cve.summary,
                'cvss2': cve.cvss2,
                'cvss3': cve.cvss3,
                'urls': urls,
                'cwes': cwes  # Include CWEs in the data
            }
            cve_data.append(data)
            print(f"[DEBUG] Retrieved CVE: {data}")

    # Update the last printed CVE to the most recent one processed
    if cve_data:
        last_printed_cve = max(data['updated_at'] for data in cve_data)
        print(f"[INFO] Updated last printed CVE timestamp to {last_printed_cve}")

    session.close()
    return cve_data

def insert_or_update_cve(session, data):
    # Check if the CVE already exists
    cve = session.query(AegixCve).filter_by(cve_id=data['cve_id']).first()
    if cve:
        print(f"[DEBUG] Updating existing CVE: {data['cve_id']}")
        cve.summary = data['summary']
        cve.cvss2 = data['cvss2']
        cve.cvss3 = data['cvss3']
        cve.updated_at = data['updated_at']
        cve.is_predicted = False
    else:
        print(f"[DEBUG] Adding new CVE: {data['cve_id']}")
        cve = AegixCve(
            cve_id=data['cve_id'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            summary=data['summary'],
            cvss2=data['cvss2'],
            cvss3=data['cvss3'],
        )
        session.add(cve)
    
    # Handle Vendors, Products, CWEs, and URLs after the CVE is inserted/updated
    session.commit()

def store_cve_data_in_aegix(cve_data):
    if not cve_data:
        print("[INFO] No CVE data to store.")
        return

    print("[INFO] Storing CVE data in Aegix database...")
    session = AegixSession()

    for data in cve_data:
        insert_or_update_cve(session, data)

    session.commit()
    session.close()

def main():
    while True:
        print("[INFO] Starting data retrieval and storage process...")
        try:
            print("[INFO] Starting the process...")
    
            # Fetch CVE data from OpenCVE
            cve_data = get_cve_data_from_opencve()

            # Store CVE data in Aegix database
            store_cve_data_in_aegix(cve_data)

            print("[INFO] Process completed.")
        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        print("[INFO] Sleeping for 10 minutes...")
        time.sleep(600)

if __name__ == "__main__":
    main()
