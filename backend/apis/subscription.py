from fastapi import APIRouter

# Create a new router instance for subscriptions
router = APIRouter()

# Sample route for subscription info
@router.get("/")
async def get_subscriptions():
    return {"message": "List of subscriptions"}

@router.post("/")
async def create_subscription():
    return {"message": "Create a new subscription"}
