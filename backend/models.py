from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from datetime import datetime, timezone
from .database import Base

# Define the PlanType model
class PlanType(Base):
    __tablename__ = "plan_types"
    plan_id = Column(Integer, primary_key=True, index=True)
    plan_name = Column(String(50), nullable=False)
    plan_price = Column(Float, nullable=False)
    immediate_notification = Column(Boolean, default=False)
    max_users = Column(Integer, nullable=False)
    max_subscriptions = Column(Integer, nullable=False)

# Define the Role model
class Role(Base):
    __tablename__ = "roles"
    role_id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String(50))

# Define the Admins model
class Admin(Base):
    __tablename__ = "admins"
    admin_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    reset_pswd_token = Column(String(50))
    role = Column(Integer, ForeignKey("roles.role_id"))

# Define the Organization model
class Organization(Base):
    __tablename__ = "organizations"
    organization_id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    plan_type = Column(Integer, ForeignKey("plan_types.plan_id"))
    max_subscriptions = Column(Integer, nullable=True)
    immediate_notification = Column(Boolean, default=False)

# Define the User model
class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.organization_id"))
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)

# Define the CWE model
class CWE(Base):
    __tablename__ = "cwes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    cwe_id = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    name = Column(String(250))
    description = Column(Text)

# Define the Vendor model
class Vendor(Base):
    __tablename__ = "vendors"
    vendor_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    vendor_name = Column(String(100), nullable=False)

# Define the Product model
class Product(Base):
    __tablename__ = "products"
    product_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    product_name = Column(String(100), nullable=False)
    vendor_id = Column(Integer, ForeignKey("vendors.vendor_id"))

# Define the CVE model
class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    summary = Column(Text)
    cvss2 = Column(Float)
    cvss3 = Column(Float)

# Define the CVE_URL model
class CVE_URL(Base):
    __tablename__ = "cves_urls"
    url_id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"))
    url = Column(Text, nullable=False)
    content = Column(Text)

# Define the Solution model
class Solution(Base):
    __tablename__ = "solutions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    solution = Column(Text)

# Define the URLSolution model
class URLSolution(Base):
    __tablename__ = "urls_solutions"
    solution_id = Column(Integer, ForeignKey("solutions.id", ondelete="CASCADE"), primary_key=True)
    url_id = Column(Integer, ForeignKey("cves_urls.url_id", ondelete="CASCADE"), primary_key=True)

# Define the Alert model
class Alert(Base):
    __tablename__ = "alerts"
    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    is_new_cve = Column(Boolean, default=True)
    is_treated = Column(Boolean, default=False)
    last_alert_id = Column(Integer)

# Define many-to-many relationships
class User_Product(Base):
    __tablename__ = "users_products"
    user_id = Column(Integer, ForeignKey("users.user_id"), primary_key=True)
    product_id = Column(Integer, ForeignKey("products.product_id"), primary_key=True)

class User_Vendor(Base):
    __tablename__ = "users_vendors"
    user_id = Column(Integer, ForeignKey("users.user_id"), primary_key=True)
    vendor_id = Column(Integer, ForeignKey("vendors.vendor_id"), primary_key=True)

class User_CWE(Base):
    __tablename__ = "users_cwes"
    user_id = Column(Integer, ForeignKey("users.user_id"), primary_key=True)
    cwe_id = Column(String(50), ForeignKey("cwes.cwe_id"), primary_key=True)

class CVE_Product(Base):
    __tablename__ = "cves_products"
    cve_id = Column(String(50), ForeignKey("cves.cve_id"), primary_key=True)
    product_id = Column(Integer, ForeignKey("products.product_id"), primary_key=True)
    is_predicted = Column(Boolean)

class CVE_Vendor(Base):
    __tablename__ = "cves_vendors"
    cve_id = Column(String(50), ForeignKey("cves.cve_id"), primary_key=True)
    vendor_id = Column(Integer, ForeignKey("vendors.vendor_id"), primary_key=True)
    is_predicted = Column(Boolean)

class CVE_CWE(Base):
    __tablename__ = "cves_cwes"
    cve_id = Column(String(50), ForeignKey("cves.cve_id"), primary_key=True)
    cwe_id = Column(String(50), ForeignKey("cwes.cwe_id"), primary_key=True)
