from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.apis.auth import router as auth_router
from backend.apis.plan import router as plan_router
from backend.apis.subscription import router as subscription_router
from backend.apis.cves import router as cves_router
from backend.apis.dashboard import router as dashboard_router
from backend.utils.config import load_settings

# Initialize FastAPI app
app = FastAPI(
    title="Aegix API",
    description="APIs for Aegix application including plan, subscription, authentication, and AI models.",
    version="1.0.0"
)

# Load application settings
settings = load_settings()

# CORS middleware (adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace '*' with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(plan_router, prefix="/api/plan", tags=["Plan"])
app.include_router(subscription_router, prefix="/api/subscriptions", tags=["Subscriptions"])
app.include_router(cves_router, prefix="/api/cves", tags=["CVEs"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard Statistics"])

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to the Aegix API"}

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}
