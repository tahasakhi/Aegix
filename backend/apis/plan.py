from fastapi import APIRouter

# Create a new router instance for plans
router = APIRouter()

# Sample route for fetching plans
@router.get("/")
async def get_plans():
    return {"message": "List of available plans"}

@router.get("/{plan_id}")
async def get_plan(plan_id: str):
    return {"message": f"Details of plan {plan_id}"}
