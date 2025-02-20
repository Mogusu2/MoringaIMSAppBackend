import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = f"postgresql://{os.getenv('SUPABASE_USER')}:{os.getenv('SUPABASE_PASSWORD')}@{os.getenv('SUPABASE_HOST')}:{os.getenv('SUPABASE_PORT')}/{os.getenv('SUPABASE_DATABASE')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # User Roles and Permissions
    ROLES_PERMISSIONS = {
        "admin": ["dashboard", "inventory", "assets", "borrow", "return", "notifications"],
        "staff": ["assets", "borrow", "return", "notifications"],
        "student": ["assets", "borrow", "return", "notifications"]
    }
