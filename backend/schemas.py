from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date

class UserBase(BaseModel):
    """
    Base model for user attributes.
    
    Attributes:
        username (str): The username of the user.
    """
    username: str
    email: Optional[EmailStr] = None

class UserCreate(UserBase):
    """
    Model for user creation.

    Attributes:
        password (str): The password for user registration.
    """
    password: Optional[str] = None

class User(UserBase):
    """
    Model representing a user.

    Attributes:
        id (int): The unique identifier for the user.
    """
    id: int

    class Config:
        orm_mode = True  # Use orm_mode to enable ORM model compatibility

class TodoItemBase(BaseModel):
    """
    Base model for to-do item attributes.

    Attributes:
        title (str): The title of the to-do item.
        description (str): The description of the to-do item.
    """
    title: str
    description: str
    deadline: date

    class Config:
        arbitrary_types_allowed = True
        orm_mode = True

class TodoItemCreate(TodoItemBase):
    """
    Model for creating a to-do item.

    Inherits attributes from TodoItemBase.
    """
    pass

class TodoItem(TodoItemBase):
    """
    Model representing a to-do item.

    Attributes:
        id (int): The unique identifier for the to-do item.
        completed (bool): The completion status of the to-do item.
        owner_id (int): The ID of the user who owns the to-do item.
    """
    id: int
    owner_id: int

    class Config:
        orm_mode = True  # Use orm_mode to enable ORM model compatibility

class Token(BaseModel):
    """
    Model representing an access token.

    Attributes:
        access_token (str): The JWT access token.
        token_type (str): The type of the token (e.g., "bearer").
    """
    access_token: str
    token_type: str

    class Config:
        orm_mode = True  # Use orm_mode to enable ORM model compatibility

class TokenData(BaseModel):
    """
    Model for token data.

    Attributes:
        username (Optional[str]): The username associated with the token.
    """
    username: Optional[str] = None

    class Config:
        orm_mode = True  # Use orm_mode to enable ORM model compatibility
