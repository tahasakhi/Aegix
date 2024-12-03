import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '../../configs/aegix.env'))

# Now you can access environment variables using os.getenv()
DATABASE_URL = os.getenv('DATABASE_URL')
SECRET_KEY = os.getenv('SECRET_KEY')
ENVIRONMENT = os.getenv('ENVIRONMENT')

def load_settings():
    return {
        "database_url": DATABASE_URL,
        "secret_key": SECRET_KEY,
        "environment": ENVIRONMENT,
    }
