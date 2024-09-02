# app/config.py
import secrets

class Settings:
    PROJECT_NAME: str = "My FastAPI Project"
    DATABASE_URL: str = "sqlite:///./test.db"  # Replace with your actual database URL
    SECRET_KEY: str = "your-secret-key"  # Replace with your actual secret key
    ALGORITHM: str = "HS256"  # The algorithm used for JWT encoding
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # Token expiration time in minutes

settings = Settings()
