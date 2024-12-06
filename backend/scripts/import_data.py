import os
import time
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError

# Database connection strings (replace with actual URLs)
OPENCVE_DATABASE_URL = os.environ['OPENCVE_DATABASE_URL']
AEGIX_DATABASE_URL = os.environ['AEGIX_DATABASE_URL']

# Separate metadata for each database
opencve_metadata = MetaData()
aegix_metadata = MetaData()

# Define models for OpenCVE database
BaseOpenCve = declarative_base(metadata=opencve_metadata)

class OpenCveVendor(BaseOpenCve):
    __tablename__ = 'vendors'
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String, unique=True, nullable=False)

class OpenCveProduct(BaseOpenCve):
    __tablename__ = 'products'
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String, nullable=False)
    vendor_id = Column(String, ForeignKey('vendors.id'))

class OpenCveCwe(BaseOpenCve):
    __tablename__ = 'cwes'
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    cwe_id = Column(String, unique=True, nullable=False)
    name = Column(String)
    description = Column(String)

# Define models for Aegix database
BaseAegix = declarative_base(metadata=aegix_metadata)

class AegixVendor(BaseAegix):
    __tablename__ = 'vendors'
    vendor_id = Column(Integer, primary_key=True)
    vendor_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

class AegixProduct(BaseAegix):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String(100), nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'))
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

class AegixCwe(BaseAegix):
    __tablename__ = 'cwes'
    id = Column(Integer, primary_key=True)
    cwe_id = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String(250))
    description = Column(String)

# Create engines for OpenCVE and Aegix databases
engine_opencve = create_engine(OPENCVE_DATABASE_URL)
engine_aegix = create_engine(AEGIX_DATABASE_URL)

# Create sessions for both databases
SessionOpenCve = sessionmaker(bind=engine_opencve)
session_opencve = SessionOpenCve()

SessionAegix = sessionmaker(bind=engine_aegix)
session_aegix = SessionAegix()

def transfer_vendors_and_products():
    try:
        # Fetch vendors from OpenCVE
        open_cve_vendors = session_opencve.query(OpenCveVendor).all()

        for vendor in open_cve_vendors:
            # Check if vendor already exists in Aegix
            existing_vendor = session_aegix.query(AegixVendor).filter_by(vendor_name=vendor.name).first()

            if not existing_vendor:
                print(f"[DEBUG] Adding new vendor: {vendor.name}")
                new_vendor = AegixVendor(
                    vendor_name=vendor.name,
                    created_at=vendor.created_at,
                    updated_at=vendor.updated_at
                )
                session_aegix.add(new_vendor)
                session_aegix.commit()

                # Retrieve the newly created vendor's ID
                existing_vendor = new_vendor  # Assign the new vendor to existing_vendor

            # Fetch products for the vendor from OpenCVE
            open_cve_products = session_opencve.query(OpenCveProduct).filter_by(vendor_id=vendor.id).all()

            for product in open_cve_products:
                # Check if product already exists in Aegix
                existing_product = session_aegix.query(AegixProduct).filter_by(product_name=product.name).first()
                if not existing_product:
                    print(f"[DEBUG] Adding new product: {product.name} under vendor: {vendor.name}")
                    # Link the product with the existing vendor in Aegix
                    new_product = AegixProduct(
                        product_name=product.name,
                        vendor_id=existing_vendor.vendor_id,  # Use the existing Aegix vendor_id
                        created_at=product.created_at,
                        updated_at=product.updated_at
                    )
                    session_aegix.add(new_product)
                    session_aegix.commit()
        print("[INFO] Vendors and products transfer completed.")
    except SQLAlchemyError as e:
        print(f"[ERROR] An error occurred while transferring vendors and products: {e}")
        session_aegix.rollback()


def transfer_cwes():
    try:
        # Fetch CWEs from OpenCVE
        open_cve_cwes = session_opencve.query(OpenCveCwe).all()

        for cwe in open_cve_cwes:
            # Check if CWE already exists in Aegix
            existing_cwe = session_aegix.query(AegixCwe).filter_by(cwe_id=cwe.cwe_id).first()
            if not existing_cwe:
                print(f"[DEBUG] Adding new CWE: {cwe.cwe_id}")
                new_cwe = AegixCwe(
                    cwe_id=cwe.cwe_id,
                    created_at=cwe.created_at,
                    updated_at=cwe.updated_at,
                    name=cwe.name,
                    description=cwe.description
                )
                session_aegix.add(new_cwe)
                session_aegix.commit()
        print("[INFO] CWEs transfer completed.")
    except SQLAlchemyError as e:
        print(f"[ERROR] An error occurred while transferring CWEs: {e}")
        session_aegix.rollback()

def main():
    transfer_vendors_and_products()
    transfer_cwes()

if __name__ == '__main__':
    main()
