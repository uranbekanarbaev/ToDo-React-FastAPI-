from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend import crud
from .database import SessionLocal, get_db

from authlib.integrations.starlette_client import OAuth

google_cliend_id = "GOOGLE_CLIENT_ID"
google_client_secret = "GOOGLE_CLIENT_SECRET"

# Constants
SECRET_KEY = "MY_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify if the provided plain password matches the hashed password.
    
    Args:
        plain_password (str): The plain text password.
        hashed_password (str): The hashed password stored in the database.
    
    Returns:
        bool: True if passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash the provided password.
    
    Args:
        password (str): The plain text password.
    
    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    """
    Authenticate a user by verifying their username and password.
    
    Args:
        db (Session): The database session.
        username (str): The username of the user.
        password (str): The plain text password of the user.
    
    Returns:
        User: The authenticated user if credentials are valid, otherwise False.
    """
    user = crud.get_user(db, username=username)
    if not user:
        return False
    if user.hashed_password is None:
        # This user is an OAuth user
        return user
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create an access token with an expiration time.
    
    Args:
        data (dict): The data to include in the token payload.
        expires_delta (Optional[timedelta]): The expiration time of the token.
    
    Returns:
        str: The encoded JWT access token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    """
    Retrieve the current user based on the provided token.
    
    Args:
        db (Session): The database session.
        token (str): The access token.
    
    Returns:
        User: The current authenticated user.
    
    Raises:
        HTTPException: If the token is invalid or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        print(f"JWTError: {e}")
        raise credentials_exception
    user = crud.get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

facebook_client_id = "FACEBOOK_CLIENT_ID"
facebook_cliend_secret = "FASEBOOK_CLIENT_SECRET"

oauth = OAuth()

oauth.register(
    name='google',
    client_id=google_cliend_id,
    client_secret=google_client_secret,
    redirect_uri='http://127.0.0.1:8000/auth/google/callback',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url= 'https://accounts.google.com/.well-known/openid-configuration',
)

oauth.register(
    name='facebook',
    client_id=facebook_client_id,
    client_secret=facebook_cliend_secret,
    authorize_url='https://www.facebook.com/dialog/oauth',
    access_token_url='https://graph.facebook.com/v4.0/oauth/access_token',
    redirect_uri='https://cda9-213-109-66-248.ngrok-free.app/auth/google/callback',
    client_kwargs={'scope': 'email public_profile'},
)

