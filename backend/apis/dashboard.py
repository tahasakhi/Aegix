from fastapi import APIRouter

# Create a new router instance for dashboard statistics
router = APIRouter()

# Sample route for dashboard data
@router.get("/stats")
async def get_dashboard_stats():
    return {"message": "Dashboard statistics"}
