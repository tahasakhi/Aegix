from fastapi import APIRouter

# Create a new router instance for authentication
router = APIRouter()

# Sample authentication route
@router.get("/login")
async def login():
    return {"message": "Login endpoint"}

@router.post("/register")
async def register():
    return {"message": "Registration endpoint"}
