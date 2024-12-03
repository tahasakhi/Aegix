from fastapi import APIRouter

# Create a new router instance for CVEs
router = APIRouter()

# Sample route for listing CVEs
@router.get("/")
async def get_cves():
    return {"message": "List of CVEs"}

@router.get("/{cve_id}")
async def get_cve(cve_id: str):
    return {"message": f"Details of CVE {cve_id}"}
